/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alipay.application.service.system.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.dao.mapper.OpenApiAuthMapper;
import com.alipay.dao.po.OpenApiAuthPO;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Send the secretKey to the calling system for the calling system to call the portal system interface for authentication.
 * The request headers for calling the system include App-Key (calling system name), Timestamp (timestamp), App-Sign
 * appSign generation rules: DigestUtils.md5Hex(accessKey + timestamp + secretKey)
 * <p>
 * After receiving the request, parse the request header field and generate appSign locally,
 * Rule: DigestUtils.md5Hex(accessKey + timestamp + secretKey)
 * Then compare whether the two are the same, if they are the same, they are released, if they are different, they are truncated.
 */
@Component
public class DigestSignUtils {

    private static final Logger logger = LoggerFactory.getLogger(DigestSignUtils.class);
    
    @Resource
    private OpenApiAuthMapper openApiAuthMapper;

    public static final String TIMESTAMP = "timestamp";
    public static final String ACCESS_KEY_NAME = "access-key";
    public static final String SIGN = "sign";
    
    // Timestamp validity window in seconds (5 minutes)
    private static final long TIMESTAMP_VALIDITY_WINDOW = 300;
    
    // Maximum length for input parameters to prevent DoS attacks
    private static final int MAX_PARAM_LENGTH = 256;
    
    // Delimiter for secure string concatenation
    private static final String DELIMITER = "|";

    /**
     * Authenticate API request using signature verification
     * 
     * @param request HTTP request containing authentication headers
     * @return ApiResponse indicating authentication result
     */
    public ApiResponse<String> isAuth(HttpServletRequest request) {
        try {
            Map<String, String> headerMap = getHeadersInfo(request);
            if (headerMap.isEmpty()) {
                logger.warn("Authentication failed: empty headers");
                return new ApiResponse<>(ApiResponse.ACCESS_DENIED, "Authentication failed");
            }

            String timeStamp = MapUtils.getString(headerMap, TIMESTAMP);
            String accessKey = MapUtils.getString(headerMap, ACCESS_KEY_NAME);
            String appSign = MapUtils.getString(headerMap, SIGN);
            
            // Validate input parameters
            if (!isValidInput(timeStamp, accessKey, appSign)) {
                logger.warn("Authentication failed: invalid input parameters");
                return new ApiResponse<>(ApiResponse.ACCESS_DENIED, "Authentication failed");
            }

            // Validate timestamp to prevent replay attacks
            if (!isValidTimestamp(timeStamp)) {
                logger.warn("Authentication failed: invalid timestamp for accessKey: {}", accessKey);
                return new ApiResponse<>(ApiResponse.ACCESS_DENIED, "Authentication failed");
            }

            OpenApiAuthPO openApiAuthPO = openApiAuthMapper.findByAccessKey(accessKey);
            if (Objects.isNull(openApiAuthPO) || Strings.isBlank(openApiAuthPO.getSecretKey())) {
                logger.warn("Authentication failed: invalid credentials for accessKey: {}", accessKey);
                return new ApiResponse<>(ApiResponse.ACCESS_DENIED, "Authentication failed");
            }

            // Generate signature using SHA-256 with secure concatenation including request parameters
            String systemSecretKey = openApiAuthPO.getSecretKey();
            String realAppSign = generateSignatureWithParams(request, accessKey, timeStamp, systemSecretKey);

            // Compare signatures using constant-time comparison
            if (MessageDigest.isEqual(appSign.getBytes(StandardCharsets.UTF_8), 
                                    realAppSign.getBytes(StandardCharsets.UTF_8))) {
                logger.info("Authentication successful for accessKey: {}", accessKey);
                return ApiResponse.SUCCESS;
            }

            logger.warn("Authentication failed: signature mismatch for accessKey: {}", accessKey);
            return new ApiResponse<>(ApiResponse.ACCESS_DENIED, "Authentication failed");
            
        } catch (Exception e) {
            logger.error("Authentication error: {}", e.getMessage(), e);
            return new ApiResponse<>(ApiResponse.ACCESS_DENIED, "Authentication failed");
        }
    }

    /**
     * Validate input parameters for null, empty, and length constraints
     * 
     * @param timeStamp timestamp parameter
     * @param accessKey access key parameter
     * @param appSign application signature parameter
     * @return true if all parameters are valid, false otherwise
     */
    private boolean isValidInput(String timeStamp, String accessKey, String appSign) {
        return !StringUtils.isEmpty(timeStamp) && timeStamp.length() <= MAX_PARAM_LENGTH &&
               !StringUtils.isEmpty(accessKey) && accessKey.length() <= MAX_PARAM_LENGTH &&
               !StringUtils.isEmpty(appSign) && appSign.length() <= MAX_PARAM_LENGTH;
    }
    
    /**
     * Validate timestamp to prevent replay attacks
     * 
     * @param timeStamp timestamp string in seconds
     * @return true if timestamp is within valid window, false otherwise
     */
    private boolean isValidTimestamp(String timeStamp) {
        try {
            long requestTime = Long.parseLong(timeStamp);
            long currentTime = Instant.now().getEpochSecond();
            long timeDifference = Math.abs(currentTime - requestTime);
            return timeDifference <= TIMESTAMP_VALIDITY_WINDOW;
        } catch (NumberFormatException e) {
            logger.warn("Invalid timestamp format: {}", timeStamp);
            return false;
        }
    }
    
    /**
     * Generate SHA-256 signature including request parameters
     *
     * @param request the HTTP servlet request
     * @param accessKey the access key
     * @param timeStamp the timestamp
     * @param secretKey the secret key
     * @return SHA-256 signature in hexadecimal format
     */
    private static String generateSignatureWithParams(HttpServletRequest request, String accessKey, String timeStamp, String secretKey) {
         try {
             // Get all request parameters and build sorted parameter string
             Map<String, String> allParams = getAllRequestParams(request);
             String sortedParamString = buildSortedParamString(allParams);
             
             // Use secure string concatenation with delimiter: accessKey|timestamp|sortedParams|secretKey
             String data = accessKey + DELIMITER + timeStamp + DELIMITER + sortedParamString + DELIMITER + secretKey;
             
             MessageDigest digest = MessageDigest.getInstance("SHA-256");
             byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
             return bytesToHex(hash);
         } catch (NoSuchAlgorithmException e) {
              logger.error("SHA-256 algorithm not available", e);
              throw new RuntimeException("Signature generation failed", e);
          }
     }

    /**
      * Get all request parameters from the HTTP request
      * Supports both URL query parameters and JSON request body parameters
      *
      * @param request the HTTP servlet request
      * @return map of all request parameters
      */
     private static Map<String, String> getAllRequestParams(HttpServletRequest request) {
         LinkedHashMap<String, String> params = new LinkedHashMap<>();
         
         // Get URL query parameters
         Enumeration<String> paramNames = request.getParameterNames();
         while (paramNames.hasMoreElements()) {
             String paramName = paramNames.nextElement();
             String paramValue = request.getParameter(paramName);
             // Exclude authentication-related parameters and validate length
              if (paramValue != null && paramValue.length() <= MAX_PARAM_LENGTH 
                      && !ACCESS_KEY_NAME.equals(paramName) && !TIMESTAMP.equals(paramName) && !SIGN.equals(paramName)) {
                 params.put(paramName, paramValue);
             }
         }
         
         // Extract parameters from JSON request body for POST requests
         if ("POST".equalsIgnoreCase(request.getMethod())) {
             String contentType = request.getContentType();
             if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                 Map<String, String> jsonParams = extractJsonParams(request);
                 // Merge JSON parameters with query parameters, JSON params take precedence
                 for (Map.Entry<String, String> entry : jsonParams.entrySet()) {
                     String paramName = entry.getKey();
                     String paramValue = entry.getValue();
                     if (paramValue != null && paramValue.length() <= MAX_PARAM_LENGTH 
                             && !ACCESS_KEY_NAME.equals(paramName) && !TIMESTAMP.equals(paramName) && !SIGN.equals(paramName)) {
                         params.put(paramName, paramValue);
                     }
                 }
             }
         }
         
         return params;
     }
 
    /**
     * Extract parameters from JSON request body
     * Handles cases where the request body has already been read by using a cached wrapper
     *
     * @param request the HTTP servlet request
     * @return map of parameters extracted from JSON body
     */
    private static Map<String, String> extractJsonParams(HttpServletRequest request) {
        Map<String, String> params = new HashMap<>();
        
        try {
            String jsonBody = null;
            
            // Check if request is already a cached wrapper
            if (request instanceof CachedBodyHttpServletRequest) {
                jsonBody = ((CachedBodyHttpServletRequest) request).getBody();
            } else {
                // Try to read from the request directly
                // This may fail if the stream has already been consumed
                try {
                    StringBuilder sb = new StringBuilder();
                    try (BufferedReader reader = request.getReader()) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            sb.append(line);
                        }
                    }
                    jsonBody = sb.toString();
                } catch (IllegalStateException e) {
                    // getReader() has already been called, try to create a cached wrapper
                    logger.warn("Request body has already been read, attempting to create cached wrapper");
                    try {
                        CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(request);
                        jsonBody = cachedRequest.getBody();
                    } catch (Exception ex) {
                        logger.warn("Failed to create cached request wrapper: {}", ex.getMessage());
                        return params; // Return empty params if we can't read the body
                    }
                }
            }
            
            if (jsonBody != null && !jsonBody.trim().isEmpty()) {
                try {
                    JSONObject jsonObject = JSON.parseObject(jsonBody);
                    for (String key : jsonObject.keySet()) {
                        Object value = jsonObject.get(key);
                        if (value != null) {
                            // Convert all values to strings for consistent parameter handling
                            params.put(key, value.toString());
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Failed to parse JSON body: {}", e.getMessage());
                }
            }
            
        } catch (Exception e) {
            logger.warn("Failed to extract JSON parameters: {}", e.getMessage());
        }
        
        return params;
    }

     /**
      * Build sorted parameter string from parameter map
      *
      * @param params map of parameters
      * @return sorted parameter string
      */
     private static String buildSortedParamString(Map<String, String> params) {
         if (params.isEmpty()) {
             return "";
         }
         return params.entrySet().stream()
                 .sorted(Map.Entry.comparingByKey())
                 .map(entry -> entry.getKey() + "=" + entry.getValue())
                 .collect(Collectors.joining("&"));
     }

    /**
     * Generate SHA-256 signature using secure string concatenation
     * 
     * @param accessKey access key
     * @param timeStamp timestamp
     * @param secretKey secret key
     * @return SHA-256 hex signature
     */
    private String generateSHA256Signature(String accessKey, String timeStamp, String secretKey) {
        try {
            String data = accessKey + DELIMITER + timeStamp + DELIMITER + secretKey;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            logger.error("SHA-256 algorithm not available", e);
            throw new RuntimeException("Cryptographic error", e);
        }
    }

    /**
     * Get the request header field key-value
     *
     * @param request req
     * @return java.util.Map<java.lang.String, java.lang.String>
     */
    private Map<String, String> getHeadersInfo(HttpServletRequest request) {
        Map<String, String> map = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        /*
         *     Enumeration keys costs 6 milliseconds
         * 　　Enumeration elements costs 5 milliseconds
         * 　　Iterator keySet costs 10 milliseconds
         * 　　Iterator entrySet costs 10 milliseconds
         */
        while (headerNames.hasMoreElements()) {
            String key = headerNames.nextElement();
            String value = request.getHeader(key);
            map.put(key, value);
        }
        return map;
    }

    public static String generateKey(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    /**
     * Convert byte array to lowercase hexadecimal string
     * 
     * @param bytes byte array to convert
     * @return lowercase hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

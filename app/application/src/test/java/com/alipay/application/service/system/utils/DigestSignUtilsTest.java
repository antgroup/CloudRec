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

import com.alipay.application.share.vo.ApiResponse;
import com.alipay.dao.mapper.OpenApiAuthMapper;
import com.alipay.dao.po.OpenApiAuthPO;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for DigestSignUtils class
 * Tests cover authentication, signature generation, parameter validation, and security features
 */
@ExtendWith(MockitoExtension.class)
class DigestSignUtilsTest {

    @Mock
    private OpenApiAuthMapper openApiAuthMapper;

    @InjectMocks
    private DigestSignUtils digestSignUtils;

    private MockHttpServletRequest mockRequest;
    private OpenApiAuthPO mockOpenApiAuthPO;

    private static final String TEST_ACCESS_KEY = "test-access-key-12345";
    private static final String TEST_SECRET_KEY = "test-secret-key-67890";
    private static final String TEST_TIMESTAMP = String.valueOf(Instant.now().getEpochSecond());
    private static final String INVALID_TIMESTAMP = String.valueOf(Instant.now().getEpochSecond() - 400); // 400 seconds ago

    /**
     * Set up test fixtures before each test method
     */
    @BeforeEach
    void setUp() {
        mockRequest = new MockHttpServletRequest();
        mockOpenApiAuthPO = new OpenApiAuthPO();
        mockOpenApiAuthPO.setAccessKey(TEST_ACCESS_KEY);
        mockOpenApiAuthPO.setSecretKey(TEST_SECRET_KEY);
    }

    /**
     * Test successful authentication with valid parameters
     */
    @Test
    void testIsAuth_Success() throws Exception {
        // Arrange
        mockRequest.addHeader("access-key", TEST_ACCESS_KEY);
        mockRequest.addHeader("timestamp", TEST_TIMESTAMP);
        mockRequest.addParameter("param1", "value1");
        mockRequest.addParameter("param2", "value2");

        // Generate signature with parameters using the same logic as generateSignatureWithParams
        String sortedParams = "param1=value1&param2=value2"; // Sorted parameters
        String data = TEST_ACCESS_KEY + "|" + TEST_TIMESTAMP + "|" + sortedParams + "|" + TEST_SECRET_KEY;
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        String validSign = sb.toString();

        mockRequest.addHeader("sign", validSign);

        when(openApiAuthMapper.findByAccessKey(TEST_ACCESS_KEY)).thenReturn(mockOpenApiAuthPO);

        // Act
        ApiResponse<String> result = digestSignUtils.isAuth(mockRequest);

        // Assert
        assertEquals(ApiResponse.SUCCESS_CODE, result.getCode());
        assertEquals("success", result.getMsg());
        verify(openApiAuthMapper).findByAccessKey(TEST_ACCESS_KEY);
    }

    /**
     * Test authentication failure with missing access key
     */
    @Test
    void testIsAuth_MissingAccessKey() {
        // Arrange
        mockRequest.addHeader("timestamp", TEST_TIMESTAMP);
        mockRequest.addHeader("sign", "some-sign");

        // Act
        ApiResponse<String> result = digestSignUtils.isAuth(mockRequest);

        // Assert
        assertEquals(ApiResponse.ACCESS_DENIED, result.getCode());
        assertEquals("Authentication failed", result.getMsg());
        verifyNoInteractions(openApiAuthMapper);
    }

    /**
     * Test authentication failure with missing timestamp
     */
    @Test
    void testIsAuth_MissingTimestamp() {
        // Arrange
        mockRequest.addHeader("access-key", TEST_ACCESS_KEY);
        mockRequest.addHeader("sign", "some-sign");

        // Act
        ApiResponse<String> result = digestSignUtils.isAuth(mockRequest);

        // Assert
        assertEquals(ApiResponse.ACCESS_DENIED, result.getCode());
        assertEquals("Authentication failed", result.getMsg());
        verifyNoInteractions(openApiAuthMapper);
    }

    /**
     * Test authentication failure with missing signature
     */
    @Test
    void testIsAuth_MissingSignature() {
        // Arrange
        mockRequest.addHeader("access-key", TEST_ACCESS_KEY);
        mockRequest.addHeader("timestamp", TEST_TIMESTAMP);

        // Act
        ApiResponse<String> result = digestSignUtils.isAuth(mockRequest);

        // Assert
        assertEquals(ApiResponse.ACCESS_DENIED, result.getCode());
        assertEquals("Authentication failed", result.getMsg());
        verifyNoInteractions(openApiAuthMapper);
    }

    /**
     * Test authentication failure with expired timestamp
     */
    @Test
    void testIsAuth_ExpiredTimestamp() {
        // Arrange
        mockRequest.addHeader("access-key", TEST_ACCESS_KEY);
        mockRequest.addHeader("timestamp", INVALID_TIMESTAMP);
        mockRequest.addHeader("sign", "some-sign");

        // Act
        ApiResponse<String> result = digestSignUtils.isAuth(mockRequest);

        // Assert
        assertEquals(ApiResponse.ACCESS_DENIED, result.getCode());
        assertEquals("Authentication failed", result.getMsg());
        verifyNoInteractions(openApiAuthMapper);
    }

    /**
     * Test authentication failure with non-existent access key
     */
    @Test
    void testIsAuth_NonExistentAccessKey() {
        // Arrange
        mockRequest.addHeader("access-key", "non-existent-key");
        mockRequest.addHeader("timestamp", TEST_TIMESTAMP);
        mockRequest.addHeader("sign", "some-sign");

        when(openApiAuthMapper.findByAccessKey("non-existent-key")).thenReturn(null);

        // Act
        ApiResponse<String> result = digestSignUtils.isAuth(mockRequest);

        // Assert
        assertEquals(ApiResponse.ACCESS_DENIED, result.getCode());
        assertEquals("Authentication failed", result.getMsg());
        verify(openApiAuthMapper).findByAccessKey("non-existent-key");
    }

    /**
     * Test authentication failure with invalid signature
     */
    @Test
    void testIsAuth_InvalidSignature() {
        // Arrange
        mockRequest.addHeader("access-key", TEST_ACCESS_KEY);
        mockRequest.addHeader("timestamp", TEST_TIMESTAMP);
        mockRequest.addHeader("sign", "invalid-signature");

        when(openApiAuthMapper.findByAccessKey(TEST_ACCESS_KEY)).thenReturn(mockOpenApiAuthPO);

        // Act
        ApiResponse<String> result = digestSignUtils.isAuth(mockRequest);

        // Assert
        assertEquals(ApiResponse.ACCESS_DENIED, result.getCode());
        assertEquals("Authentication failed", result.getMsg());
        verify(openApiAuthMapper).findByAccessKey(TEST_ACCESS_KEY);
    }

    /**
     * Test authentication with request parameters included in signature
     */
    @Test
    void testIsAuth_WithRequestParameters() throws Exception {
        // Arrange
        mockRequest.addHeader("access-key", TEST_ACCESS_KEY);
        mockRequest.addHeader("timestamp", TEST_TIMESTAMP);
        mockRequest.addParameter("param1", "value1");
        mockRequest.addParameter("param2", "value2");

        // Generate signature with parameters using the same logic as generateSignatureWithParams
        String sortedParams = "param1=value1&param2=value2"; // Sorted parameters
        String data = TEST_ACCESS_KEY + "|" + TEST_TIMESTAMP + "|" + sortedParams + "|" + TEST_SECRET_KEY;
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        String validSign = sb.toString();

        mockRequest.addHeader("sign", validSign);

        when(openApiAuthMapper.findByAccessKey(TEST_ACCESS_KEY)).thenReturn(mockOpenApiAuthPO);

        // Act
        ApiResponse<String> result = digestSignUtils.isAuth(mockRequest);

        // Assert
        assertEquals(ApiResponse.SUCCESS_CODE, result.getCode());
        assertEquals("success", result.getMsg());
    }

    /**
     * Test parameter validation with oversized parameter
     */
    @Test
    void testIsAuth_OversizedParameter() throws Exception {
        // Arrange
        String longValue = "a".repeat(300); // Exceeds MAX_PARAM_LENGTH (256)
        mockRequest.addHeader("access-key", TEST_ACCESS_KEY);
        mockRequest.addHeader("timestamp", TEST_TIMESTAMP);
        mockRequest.addParameter("longParam", longValue);

        String validSign = generateTestSignature(TEST_ACCESS_KEY, TEST_TIMESTAMP, TEST_SECRET_KEY);
        mockRequest.addHeader("sign", validSign);

        when(openApiAuthMapper.findByAccessKey(TEST_ACCESS_KEY)).thenReturn(mockOpenApiAuthPO);

        // Act
        ApiResponse<String> result = digestSignUtils.isAuth(mockRequest);

        // Assert
        assertEquals(ApiResponse.SUCCESS_CODE, result.getCode()); // Should succeed as oversized params are filtered out
    }

    /**
     * Test generateKey method with valid input
     */
    @Test
    void testGenerateKey_ValidInput() throws NoSuchAlgorithmException {
        // Arrange
        String input = "test-input";

        // Act
        String result = DigestSignUtils.generateKey(input);

        // Assert
        assertNotNull(result);
        assertEquals(32, result.length()); // MD5 produces 32-character hex string
        assertTrue(result.matches("[a-f0-9]+")); // Should be lowercase hexadecimal
    }

    /**
     * Test generateKey method with empty input
     */
    @Test
    void testGenerateKey_EmptyInput() throws NoSuchAlgorithmException {
        // Arrange
        String input = "";

        // Act
        String result = DigestSignUtils.generateKey(input);

        // Assert
        assertNotNull(result);
        assertEquals(32, result.length());
    }

    /**
     * Test generateKey method with null input
     */
    @Test
    void testGenerateKey_NullInput() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            DigestSignUtils.generateKey(null);
        });
    }

    /**
     * Test isValidInput method using reflection
     */
    @Test
    void testIsValidInput() throws Exception {
        // Arrange
        Method method = DigestSignUtils.class.getDeclaredMethod("isValidInput",
                String.class, String.class, String.class);
        method.setAccessible(true);

        // Act & Assert
        assertTrue((Boolean) method.invoke(digestSignUtils, TEST_TIMESTAMP, TEST_ACCESS_KEY, "valid-sign"));
        assertFalse((Boolean) method.invoke(digestSignUtils, null, TEST_ACCESS_KEY, "valid-sign"));
        assertFalse((Boolean) method.invoke(digestSignUtils, TEST_TIMESTAMP, null, "valid-sign"));
        assertFalse((Boolean) method.invoke(digestSignUtils, TEST_TIMESTAMP, TEST_ACCESS_KEY, null));
        assertFalse((Boolean) method.invoke(digestSignUtils, "", TEST_ACCESS_KEY, "valid-sign"));

        // Test with oversized parameters
        String longString = "a".repeat(300);
        assertFalse((Boolean) method.invoke(digestSignUtils, longString, TEST_ACCESS_KEY, "valid-sign"));
        assertFalse((Boolean) method.invoke(digestSignUtils, TEST_TIMESTAMP, longString, "valid-sign"));
        assertFalse((Boolean) method.invoke(digestSignUtils, TEST_TIMESTAMP, TEST_ACCESS_KEY, longString));
    }

    /**
     * Test isValidTimestamp method using reflection
     */
    @Test
    void testIsValidTimestamp() throws Exception {
        // Arrange
        Method method = DigestSignUtils.class.getDeclaredMethod("isValidTimestamp", String.class);
        method.setAccessible(true);

        String currentTimestamp = String.valueOf(Instant.now().getEpochSecond());
        String expiredTimestamp = String.valueOf(Instant.now().getEpochSecond() - 400);
        String futureTimestamp = String.valueOf(Instant.now().getEpochSecond() + 100);

        // Act & Assert
        assertTrue((Boolean) method.invoke(digestSignUtils, currentTimestamp));
        assertFalse((Boolean) method.invoke(digestSignUtils, expiredTimestamp));
        assertTrue((Boolean) method.invoke(digestSignUtils, futureTimestamp)); // Future timestamps within window are valid
        assertFalse((Boolean) method.invoke(digestSignUtils, "invalid-timestamp"));
    }

    /**
     * Test getAllRequestParams method using reflection
     */
    @Test
    void testGetAllRequestParams() throws Exception {
        // Arrange
        Method method = DigestSignUtils.class.getDeclaredMethod("getAllRequestParams", HttpServletRequest.class);
        method.setAccessible(true);

        mockRequest.addParameter("param1", "value1");
        mockRequest.addParameter("param2", "value2");
        mockRequest.addParameter("access-key", TEST_ACCESS_KEY); // Should be excluded
        mockRequest.addParameter("timestamp", TEST_TIMESTAMP); // Should be excluded
        mockRequest.addParameter("sign", "some-sign"); // Should be excluded

        // Act
        @SuppressWarnings("unchecked")
        Map<String, String> result = (Map<String, String>) method.invoke(null, mockRequest);

        // Assert
        assertEquals(2, result.size());
        assertEquals("value1", result.get("param1"));
        assertEquals("value2", result.get("param2"));
        assertFalse(result.containsKey("access-key"));
        assertFalse(result.containsKey("timestamp"));
        assertFalse(result.containsKey("sign"));
    }

    /**
     * Test buildSortedParamString method using reflection
     */
    @Test
    void testBuildSortedParamString() throws Exception {
        // Arrange
        Method method = DigestSignUtils.class.getDeclaredMethod("buildSortedParamString", Map.class);
        method.setAccessible(true);

        Map<String, String> params = new HashMap<>();
        params.put("zebra", "last");
        params.put("alpha", "first");
        params.put("beta", "second");

        // Act
        String result = (String) method.invoke(null, params);

        // Assert
        assertEquals("alpha=first&beta=second&zebra=last", result);
    }

    /**
     * Test buildSortedParamString with empty map
     */
    @Test
    void testBuildSortedParamString_EmptyMap() throws Exception {
        // Arrange
        Method method = DigestSignUtils.class.getDeclaredMethod("buildSortedParamString", Map.class);
        method.setAccessible(true);

        Map<String, String> emptyParams = new HashMap<>();

        // Act
        String result = (String) method.invoke(null, emptyParams);

        // Assert
        assertEquals("", result);
    }

    /**
     * Test signature consistency between different methods
     */
    @Test
    void testSignatureConsistency() throws Exception {
        // Arrange
        String accessKey = "test-key";
        String timestamp = "1234567890";
        String secretKey = "test-secret";

        // Create a mock request without parameters
        MockHttpServletRequest emptyRequest = new MockHttpServletRequest();

        // Act - Get signature from generateSignatureWithParams with empty request
        Method generateWithParamsMethod = DigestSignUtils.class.getDeclaredMethod("generateSignatureWithParams",
                HttpServletRequest.class, String.class, String.class, String.class);
        generateWithParamsMethod.setAccessible(true);
        String signatureWithParams = (String) generateWithParamsMethod.invoke(null, emptyRequest, accessKey, timestamp, secretKey);

        // Generate expected signature using the same format as generateSignatureWithParams
        // Format: accessKey|timestamp|sortedParams|secretKey (empty sortedParams for no parameters)
        String data = accessKey + "|" + timestamp + "|" + "" + "|" + secretKey;
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        String expectedSignature = sb.toString();

        // Assert
        assertNotNull(signatureWithParams);
        assertNotNull(expectedSignature);
        assertEquals(expectedSignature, signatureWithParams); // Should be equal when no parameters
    }

    /**
     * Helper method to generate test signature using reflection
     */
    private String generateTestSignature(String accessKey, String timestamp, String secretKey) throws Exception {
        // Use the same logic as generateSignatureWithParams method
        // Format: accessKey|timestamp|sortedParams|secretKey (empty sortedParams for no parameters)
        String data = accessKey + "|" + timestamp + "|" + "" + "|" + secretKey;
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
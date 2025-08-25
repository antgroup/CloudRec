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
package com.alipay.api.config.filter.annotation.aop;

import com.alipay.api.config.filter.service.RateLimitService;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.context.UserInfoDTO;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Rate limiting aspect for intercepting methods annotated with @RateLimit
 * Implements rate limiting logic using sliding window algorithm
 * 
 * @author jietian
 * @version 1.0
 * @since 2024
 */
@Aspect
@Component
@Slf4j
public class RateLimitAspect {
    
    @Resource
    private RateLimitService rateLimitService;
    
    /**
     * Around advice for rate limiting
     * Intercepts method calls annotated with @RateLimit and applies rate limiting logic
     * 
     * @param joinPoint the join point representing the intercepted method
     * @param rateLimit the rate limit annotation
     * @return the result of the method execution or rate limit error response
     * @throws Throwable if method execution fails
     */
    @Around("@annotation(rateLimit)")
    public Object rateLimit(ProceedingJoinPoint joinPoint, RateLimit rateLimit) throws Throwable {
        try {
            // Generate rate limiting key based on strategy
            String rateLimitKey = generateRateLimitKey(rateLimit.keyStrategy(), joinPoint);
            
            // Check if request is allowed
            boolean allowed = rateLimitService.isAllowed(
                    rateLimitKey, 
                    rateLimit.maxRequests(), 
                    rateLimit.timeWindowSeconds()
            );
            
            if (!allowed) {
                log.warn("Rate limit exceeded for key: {}, method: {}.{}", 
                        rateLimitKey, 
                        joinPoint.getTarget().getClass().getSimpleName(),
                        joinPoint.getSignature().getName());
                
                // Return rate limit exceeded response
                return createRateLimitResponse(rateLimit.message());
            }
            
            // Proceed with method execution
            return joinPoint.proceed();
            
        } catch (Exception e) {
            log.error("Error in rate limiting aspect for method: {}.{}", 
                    joinPoint.getTarget().getClass().getSimpleName(),
                    joinPoint.getSignature().getName(), e);
            
            // In case of error, allow the request to proceed
            return joinPoint.proceed();
        }
    }
    
    /**
     * Generate rate limiting key based on the specified strategy
     * 
     * @param strategy the key generation strategy
     * @param joinPoint the join point for method context
     * @return the generated rate limiting key
     */
    private String generateRateLimitKey(RateLimit.KeyStrategy strategy, ProceedingJoinPoint joinPoint) {
        String methodName = joinPoint.getTarget().getClass().getSimpleName() + "." + joinPoint.getSignature().getName();
        
        switch (strategy) {
            case IP:
                return "rate_limit:ip:" + getClientIpAddress() + ":" + methodName;
            case USER:
                return "rate_limit:user:" + getCurrentUserId() + ":" + methodName;
            case GLOBAL:
                return "rate_limit:global:" + methodName;
            default:
                return "rate_limit:ip:" + getClientIpAddress() + ":" + methodName;
        }
    }
    
    /**
     * Get client IP address from HTTP request
     * 
     * @return client IP address
     */
    private String getClientIpAddress() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            HttpServletRequest request = attributes.getRequest();
            
            // Check for IP address in various headers (for proxy scenarios)
            String ipAddress = request.getHeader("X-Forwarded-For");
            if (StringUtils.isBlank(ipAddress) || "unknown".equalsIgnoreCase(ipAddress)) {
                ipAddress = request.getHeader("Proxy-Client-IP");
            }
            if (StringUtils.isBlank(ipAddress) || "unknown".equalsIgnoreCase(ipAddress)) {
                ipAddress = request.getHeader("WL-Proxy-Client-IP");
            }
            if (StringUtils.isBlank(ipAddress) || "unknown".equalsIgnoreCase(ipAddress)) {
                ipAddress = request.getHeader("HTTP_CLIENT_IP");
            }
            if (StringUtils.isBlank(ipAddress) || "unknown".equalsIgnoreCase(ipAddress)) {
                ipAddress = request.getHeader("HTTP_X_FORWARDED_FOR");
            }
            if (StringUtils.isBlank(ipAddress) || "unknown".equalsIgnoreCase(ipAddress)) {
                ipAddress = request.getRemoteAddr();
            }
            
            // Handle multiple IPs in X-Forwarded-For header
            if (StringUtils.isNotBlank(ipAddress) && ipAddress.contains(",")) {
                ipAddress = ipAddress.split(",")[0].trim();
            }
            
            return StringUtils.isNotBlank(ipAddress) ? ipAddress : "unknown";
        } catch (Exception e) {
            log.warn("Failed to get client IP address", e);
            return "unknown";
        }
    }
    
    /**
     * Get current authenticated user ID
     * 
     * @return user ID or "anonymous" if not authenticated
     */
    private String getCurrentUserId() {
        try {
            UserInfoDTO userInfo = UserInfoContext.getCurrentUser();
            if (userInfo != null && StringUtils.isNotBlank(userInfo.getUserId())) {
                return userInfo.getUserId();
            }
        } catch (Exception e) {
            log.debug("Failed to get current user ID", e);
        }
        return "anonymous";
    }
    
    /**
     * Create rate limit exceeded response
     * 
     * @param message custom error message
     * @return API response indicating rate limit exceeded
     */
    private ApiResponse<Object> createRateLimitResponse(String message) {
        return new ApiResponse<>(HttpStatus.TOO_MANY_REQUESTS.value(), message);
    }
}
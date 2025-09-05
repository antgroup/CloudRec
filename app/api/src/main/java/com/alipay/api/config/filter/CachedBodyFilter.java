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
package com.alipay.api.config.filter;

import com.alipay.application.service.system.utils.CachedBodyHttpServletRequest;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Filter to cache request body for multiple reads
 * This filter wraps POST requests with JSON content type to allow
 * multiple components to read the request body without conflicts
 */
@Component
@Order(1) // Execute early in the filter chain
public class CachedBodyFilter implements Filter {
    
    private static final Logger logger = LoggerFactory.getLogger(CachedBodyFilter.class);
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        if (request instanceof HttpServletRequest httpRequest) {
            // Only wrap POST requests with JSON content type
            if ("POST".equalsIgnoreCase(httpRequest.getMethod())) {
                String contentType = httpRequest.getContentType();
                if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                    try {
                        // Wrap the request to cache the body
                        CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(httpRequest);
                        logger.debug("Wrapped POST request with JSON content type for caching");
                        chain.doFilter(cachedRequest, response);
                        return;
                    } catch (Exception e) {
                        logger.warn("Failed to wrap request for body caching: {}", e.getMessage());
                        // Fall through to process the original request
                    }
                }
            }
        }
        
        // For non-POST requests or requests without JSON content type, proceed normally
        chain.doFilter(request, response);
    }
    
    @Override
    public void init(FilterConfig filterConfig) {
        logger.info("CachedBodyFilter initialized");
    }
    
    @Override
    public void destroy() {
        logger.info("CachedBodyFilter destroyed");
    }
}
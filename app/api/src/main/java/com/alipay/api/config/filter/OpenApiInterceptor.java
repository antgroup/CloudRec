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

import com.alipay.api.config.filter.annotation.aop.OpenApi;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.AsyncHandlerInterceptor;

/**
 * 拦截器，用于检测方法上是否有@OpenApi注解，如果有则放行
 */
@Component
public class OpenApiInterceptor implements AsyncHandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(OpenApiInterceptor.class);

    /**
     * 用于标记请求是否为OpenApi请求的属性名
     */
    public static final String OPEN_API_REQUEST_ATTRIBUTE = "OPEN_API_REQUEST";

    @Override
    public boolean preHandle(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Object handler) {
        // 对于OPTIONS请求直接放行
        if (HttpMethod.OPTIONS.toString().equals(request.getMethod())) {
            return true;
        }

        // 检查处理器是否为HandlerMethod类型
        if (handler instanceof HandlerMethod handlerMethod) {
            // 检查方法上是否有@OpenApi注解
            if (handlerMethod.hasMethodAnnotation(OpenApi.class)) {
                logger.debug("Detected @OpenApi annotation on method: {}", handlerMethod.getMethod().getName());
                // 在请求属性中标记这是一个OpenApi请求
                request.setAttribute(OPEN_API_REQUEST_ATTRIBUTE, Boolean.TRUE);
                // 有@OpenApi注解的方法直接放行，认证由OpenApiAspect处理
                return true;
            }
        }

        // 没有@OpenApi注解的方法，交给下一个拦截器处理
        return true;
    }
}
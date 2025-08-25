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

import com.alipay.application.service.system.utils.TokenUtil;
import com.alipay.common.enums.Status;
import com.alipay.common.exception.BizException;
import com.alipay.common.exception.UserNoLoginException;
import com.alipay.dao.mapper.UserMapper;
import com.alipay.dao.po.UserPO;
import com.alipay.application.service.system.domain.User;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.AsyncHandlerInterceptor;

import java.util.Objects;

@Component
public class PermissionInterceptor implements AsyncHandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(PermissionInterceptor.class);

    @Resource
    private UserMapper userMapper;

    @Override
    public boolean preHandle(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Object handler) {
        // 对于OPTIONS请求直接放行
        if (HttpMethod.OPTIONS.toString().equals(request.getMethod())) {
            return true;
        }

        // 检查请求是否已被标记为OpenApi请求
        Boolean isOpenApiRequest = (Boolean) request.getAttribute(OpenApiInterceptor.OPEN_API_REQUEST_ATTRIBUTE);
        if (Boolean.TRUE.equals(isOpenApiRequest)) {
            logger.info("Skipping permission check for OpenApi request");
            return true;
        }

        // 非OpenApi请求，执行正常的权限验证
        String token = request.getHeader("token");
        if (StringUtils.isBlank(token) || "null".equals(token)) {
            throw new UserNoLoginException("Login failed");
        }

        if (StringUtils.isNotBlank(token)) {
            User user = TokenUtil.parseToken(token);
            if (Objects.isNull(user)) {
                throw new UserNoLoginException("User does not exist");
            }

            UserPO u = userMapper.findOne(user.getUserId());
            if (Objects.nonNull(u) && Status.invalid.name().equals(u.getStatus())) {
                throw new BizException("The account has been disabled, please contact the administrator to enable it");
            }
        }

        return true;
    }
}
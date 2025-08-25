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

import com.alipay.application.service.system.domain.User;
import com.alipay.application.service.system.domain.repo.UserRepository;
import com.alipay.application.service.system.utils.DigestSignUtils;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.common.exception.OpenAipNoAuthException;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.context.UserInfoDTO;
import com.alipay.dao.mapper.OpenApiAuthMapper;
import com.alipay.dao.po.OpenApiAuthPO;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;


@Aspect
@Component
public class OpenApiAspect {

    @Resource
    private DigestSignUtils digestSignUtils;
    
    @Resource
    private OpenApiAuthMapper openApiAuthMapper;
    
    @Resource
    private UserRepository userRepository;

    @Pointcut("@annotation(com.alipay.api.config.filter.annotation.aop.OpenApi)")
    public void openApiPointcut() {
    }

    @Before("openApiPointcut()")
    public void processRequest(JoinPoint joinPoint) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        ApiResponse<String> response = digestSignUtils.isAuth(request);
        if (response.getCode() != ApiResponse.SUCCESS_CODE) {
            throw new OpenAipNoAuthException(response.getMsg());
        }
        
        String accessKey = request.getHeader(DigestSignUtils.ACCESS_KEY_NAME);
        OpenApiAuthPO openApiAuthPO = openApiAuthMapper.findByAccessKey(accessKey);
        if (openApiAuthPO != null) {
            String userId = openApiAuthPO.getUserId();
            User user = userRepository.find(userId);
            if (user != null) {
                UserInfoDTO userInfoDTO = new UserInfoDTO();
                userInfoDTO.setUid(user.getId());
                userInfoDTO.setUserId(user.getUserId());
                userInfoDTO.setUsername(user.getUsername());
                userInfoDTO.setTenantId(user.getTenantId());
                UserInfoContext.setCurrentUser(userInfoDTO);
            }
        }
    }
    
    @After("openApiPointcut()")
    public void clearUserInfo() {
        UserInfoContext.clear();
    }
}

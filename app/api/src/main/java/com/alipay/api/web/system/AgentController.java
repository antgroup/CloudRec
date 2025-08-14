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
package com.alipay.api.web.system;

import com.alipay.api.config.filter.annotation.aop.AdminPermissionLimit;
import com.alipay.api.config.filter.annotation.aop.AuthenticateToken;
import com.alipay.application.service.collector.AgentService;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.application.share.request.admin.QueryAgentListRequest;
import com.alipay.application.share.request.collector.ExitAgentRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.collector.AgentRegistryVO;
import com.alipay.application.share.vo.collector.OnceTokenVO;
import com.alipay.dao.dto.AgentRegistryDTO;
import jakarta.annotation.Resource;
import org.springframework.beans.BeanUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/*
 *@title AgentController
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/8/22 17:29
 */
@RestController
@RequestMapping("/api/agentApi")
public class AgentController {

    @Resource
    private AgentService agentService;

    /**
     * Get collector list
     */
    @PostMapping("/agentList")
    public ApiResponse<ListVO<AgentRegistryVO>> queryAgentList(@Validated @RequestBody QueryAgentListRequest request,
                                                               BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        AgentRegistryDTO dto = new AgentRegistryDTO();
        BeanUtils.copyProperties(request, dto);
        return agentService.queryAgentList(dto);
    }

    /**
     * Get a one-time registration token for the collector
     */
    @AdminPermissionLimit
    @PostMapping("/getOnceToken")
    @AuthenticateToken
    public ApiResponse<OnceTokenVO> getOnceToken() {
        OnceTokenVO onceTokenVO = agentService.getOnceToken(UserInfoContext.getCurrentUser().getUserId());
        return new ApiResponse<>(onceTokenVO);
    }

    /**
     * 获取一次性注册agent用token
     */
    @AdminPermissionLimit
    @PostMapping("/exitAgent")
    public ApiResponse<String> exitAgent(ExitAgentRequest request) {
        agentService.exitAgent(request.getOnceToken());
        return ApiResponse.SUCCESS;
    }
}

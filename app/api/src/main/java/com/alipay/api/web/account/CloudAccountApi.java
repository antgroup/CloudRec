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
package com.alipay.api.web.account;

import com.alibaba.fastjson.JSON;
import com.alipay.api.config.filter.annotation.aop.AuthenticateToken;
import com.alipay.application.service.account.CloudAccountService;
import com.alipay.application.service.account.utils.PlatformUtils;
import com.alipay.application.share.request.account.*;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.account.CloudAccountVO;
import com.alipay.common.enums.Status;
import com.alipay.common.utils.ListUtils;
import com.alipay.dao.dto.CloudAccountDTO;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/*
 *@title CloudAccountApi
 *@description Cloud account related APIs
 *@author jietian
 *@version 1.0
 *@create 2024/6/20 10:51
 */
@RestController
@RequestMapping("/api/cloudAccount")
public class CloudAccountApi {

    @Resource
    private CloudAccountService cloudAccountService;

    @AuthenticateToken
    @PostMapping("/cloudAccountList")
    public ApiResponse<ListVO<CloudAccountVO>> queryCloudAccountList(HttpServletRequest httpServletRequest,
                                                                     @RequestBody QueryCloudAccountListRequest request) {
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().build();
        BeanUtils.copyProperties(request, cloudAccountDTO, "status");
        if (StringUtils.isNoneEmpty(request.getStatus())) {
            if (Arrays.asList(Status.valid.name(), Status.invalid.name()).contains(request.getStatus())) {
                cloudAccountDTO.setAccountStatus(request.getStatus());
            } else {
                cloudAccountDTO.setCollectorStatus(request.getStatus());
            }
        }

        return cloudAccountService.queryCloudAccountList(cloudAccountDTO);
    }

    @AuthenticateToken
    @PostMapping("/cloudAccountBaseInfoList")
    public ApiResponse<Map<String, Object>> queryCloudAccountBaseInfoList(@RequestBody QueryCloudAccountListRequest request) {
        return cloudAccountService.queryCloudAccountBaseInfoList(request);
    }

    @AuthenticateToken
    @PostMapping("/cloudAccountBaseInfoListV2")
    public ApiResponse<List<Map<String, Object>>> queryCloudAccountBaseInfoListV2(@RequestBody QueryCloudAccountListRequest request) {
        return cloudAccountService.queryCloudAccountBaseInfoListV2(request);
    }

    @AuthenticateToken
    @GetMapping("/cloudAccountDetail")
    public ApiResponse<CloudAccountVO> queryCloudAccountDetail(@RequestParam Long id) {
        return cloudAccountService.queryCloudAccountDetail(id);
    }

    @AuthenticateToken
    @PostMapping("/saveCloudAccount")
    public ApiResponse<String> saveCloudAccount(HttpServletRequest httpServletRequest,
                                                @Validated @RequestBody SaveCloudAccountRequest request, BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder()
                .id(request.getId())
                .cloudAccountId(request.getCloudAccountId())
                .email(request.getEmail())
                .alias(request.getAlias())
                .platform(request.getPlatform())
                .tenantId(request.getTenantId())
                .site(request.getSite())
                .owner(request.getOwner())
                .proxyConfig(request.getProxyConfig())
                .build();
        cloudAccountDTO.setResourceTypeList(ListUtils.setList(request.getResourceTypeList()));

        if (request.getCredentialsObj() != null) {
            cloudAccountDTO.setCredentialsJson(JSON.toJSONString(request.getCredentialsObj()));
            PlatformUtils.checkCredentialsJson(cloudAccountDTO.getCredentialsJson());
        }

        return cloudAccountService.saveCloudAccount(cloudAccountDTO);
    }

    @DeleteMapping("/removeCloudAccount")
    public ApiResponse<String> removeCloudAccount(@RequestParam Long id) throws IOException {
        return cloudAccountService.removeCloudAccount(id);
    }

    @PostMapping("/updateCloudAccountStatus")
    public ApiResponse<String> updateCloudAccountStatus(@Validated @RequestBody UpdateCloudAccountStatusRequest request, BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        cloudAccountService.updateCloudAccountStatus(request.getCloudAccountId(), request.getAccountStatus());
        return ApiResponse.SUCCESS;
    }

    @PostMapping("/acceptCloudAccount")
    public ApiResponse<String> acceptCloudAccount(@RequestBody @Validated AcceptAccountRequest request, BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        cloudAccountService.acceptCloudAccount(request);
        return ApiResponse.SUCCESS;
    }

    @AuthenticateToken
    @PostMapping("/createCollectTask")
    public ApiResponse<String> createCollectTask(@RequestBody CreateCollectTaskRequest request) {
        cloudAccountService.createCollectTask(request);
        return ApiResponse.SUCCESS;
    }
}

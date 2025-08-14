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
package com.alipay.api.web.openapi;


import com.alibaba.fastjson.JSON;
import com.alipay.api.config.filter.annotation.aop.OpenApi;
import com.alipay.application.service.account.CloudAccountService;
import com.alipay.application.service.account.utils.PlatformUtils;
import com.alipay.application.service.common.Platform;
import com.alipay.application.service.resource.IQueryResource;
import com.alipay.application.service.system.OpenApiService;
import com.alipay.application.service.system.TenantService;
import com.alipay.application.service.system.domain.Tenant;
import com.alipay.application.service.system.domain.enums.Status;
import com.alipay.application.service.system.utils.DigestSignUtils;
import com.alipay.application.share.request.account.CreateCollectTaskRequest;
import com.alipay.application.share.request.account.SaveCloudAccountRequest;
import com.alipay.application.share.request.admin.SaveTenantRequest;
import com.alipay.application.share.request.openapi.QueryResourceRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListScrollPageVO;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.account.CloudAccountVO;
import com.alipay.application.share.vo.resource.ResourceInstanceVO;
import com.alipay.application.share.vo.rule.RuleScanResultVO;
import com.alipay.application.share.vo.rule.RuleVO;
import com.alipay.application.share.vo.system.TenantVO;
import com.alipay.common.utils.ListUtils;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.dto.QueryScanResultDTO;
import com.alipay.dao.dto.TenantDTO;
import com.alipay.dao.mapper.CloudAccountMapper;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.PlatformPO;
import com.alipay.dao.po.ResourcePO;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Objects;

/*
 *@title OpenApiController
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/1/6 11:22
 */
@RestController
@RequestMapping("/api/open/v1")
public class OpenApiController {
    @Resource
    private OpenApiService openApiService;
    @Resource
    private Platform platform;
    @Resource
    private IQueryResource iQueryResource;
    @Resource
    private TenantService tenantService;
    @Resource
    private CloudAccountService cloudAccountService;
    @Resource
    private CloudAccountMapper cloudAccountMapper;

    /**
     * 查询扫描结果
     *
     * @param httpServletRequest httpServletRequest
     * @param queryScanResultDTO 查询条件
     * @return 扫描结果列表
     */
    @OpenApi
    @PostMapping("/queryScanResult")
    public ApiResponse<ListScrollPageVO<RuleScanResultVO>> queryScanResult(HttpServletRequest httpServletRequest, @RequestBody QueryScanResultDTO queryScanResultDTO) {
        String accessKey = httpServletRequest.getHeader(DigestSignUtils.accessKeyName);
        openApiService.checkAccessKey(accessKey, queryScanResultDTO.getTenantId());
        return openApiService.queryScanResult(queryScanResultDTO);
    }

    /**
     * 查询资源列表
     *
     * @param req 查询条件
     * @return 资源列表
     */
    @OpenApi
    @RequestMapping(value = "/queryResourceList", method = RequestMethod.POST)
    public ApiResponse<ListScrollPageVO<ResourceInstanceVO>> queryResourceList(HttpServletRequest request, @Valid @RequestBody QueryResourceRequest req) {
        return openApiService.queryResourceList(req);
    }

    /**
     * 查询规则详情
     *
     * @param ruleCode 规则CODE
     * @return 规则详情
     */
    @GetMapping("/queryRuleDetail")
    public ApiResponse<RuleVO> queryRuleDetail(@RequestParam("ruleCode") String ruleCode) {
        return openApiService.queryRuleDetail(ruleCode);
    }

    /**
     * 查询云账号列表
     *
     * @param platform 平台标识 eg:ALI_CLOUD
     * @return 云账号列表
     */
    @GetMapping("/queryCloudAccountList")
    public ApiResponse<List<CloudAccountVO>> queryCloudAccountList(String platform) {
        return openApiService.queryCloudAccountList(platform);
    }

    /**
     * Get platform type list interface
     */
    @GetMapping("/listPlatform")
    public ApiResponse<List<PlatformPO>> queryPlatformList() {
        return new ApiResponse<>(platform.queryPlatformList());
    }

    /**
     * 查询资源类型列表
     *
     * @param platform 平台
     * @return 资源类型列表
     */
    @GetMapping("/listResourceType")
    public ApiResponse<List<ResourcePO>> queryTypeList(@RequestParam(required = false) String platform) {
        return iQueryResource.queryTypeList(platform);
    }

    /**
     * 查询租户列表
     *
     * @return 租户列表
     */
    @GetMapping("/listTenant")
    public ApiResponse<ListVO<TenantVO>> listAddedTenants() {
        TenantDTO tenantDTO = new TenantDTO();
        ListVO<TenantVO> list = tenantService.findList(tenantDTO);
        return new ApiResponse<>(list);
    }

    @OpenApi
    @PostMapping("/createCollectTask")
    public ApiResponse<String> createCollectTask(@RequestBody CreateCollectTaskRequest request) {
        cloudAccountService.createCollectTask(request);
        return ApiResponse.SUCCESS;
    }

    @OpenApi
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

        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(request.getCloudAccountId());
        if (Objects.nonNull(cloudAccountPO)) {
            cloudAccountDTO.setId(cloudAccountPO.getId());
        }
        return cloudAccountService.saveCloudAccount(cloudAccountDTO);
    }

    @OpenApi
    @GetMapping("/queryAllTenantList")
    public ApiResponse<ListVO<TenantVO>> queryAllTenantList() {
        ListVO<TenantVO> listVO = tenantService.findAll();
        return new ApiResponse<>(listVO);
    }

    /**
     * Save tenant information
     */
    @OpenApi
    @PostMapping("/saveTenant")
    public ApiResponse<String> saveTenant(@Validated @RequestBody SaveTenantRequest req,
                                          BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        Tenant tenant = new Tenant(req.getId(), req.getTenantName(), Status.getStatus(req.getStatus()), req.getTenantDesc());

        tenantService.saveTenant(tenant);

        return ApiResponse.SUCCESS;
    }
}

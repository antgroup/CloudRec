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
package com.alipay.api.web.resource;

import com.alipay.api.config.filter.annotation.aop.AuthenticateToken;
import com.alipay.api.config.filter.annotation.aop.RateLimit;
import com.alipay.api.config.filter.annotation.aop.RateLimit.KeyStrategy;
import com.alipay.application.service.resource.IQueryResource;
import com.alipay.application.share.request.base.IdListRequest;
import com.alipay.application.share.request.resource.QueryGroupTypeListRequest;
import com.alipay.application.share.request.resource.QueryResourceDetailRequest;
import com.alipay.application.share.request.resource.QueryResourceExampleDataRequest;
import com.alipay.application.share.request.resource.QueryResourceListRequest;
import com.alipay.application.share.request.rule.LinkDataParam;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.resource.ResourceGroupTypeVO;
import com.alipay.application.share.vo.resource.ResourceInstanceVO;
import com.alipay.application.share.vo.resource.ResourceRiskCountVO;
import com.alipay.common.enums.AssociativeMode;
import com.alipay.common.utils.ListUtils;
import com.alipay.common.utils.PreventingSQLJoint;
import com.alipay.dao.dto.ResourceAggByInstanceTypeDTO;
import com.alipay.dao.dto.ResourceDTO;
import com.alipay.dao.po.ResourcePO;
import jakarta.annotation.Resource;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

/*
 *@title ResourceController
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/6 17:13
 */
@RestController
@RequestMapping("/api/resource")
@Validated
public class ResourceController {

    @Resource
    private IQueryResource iQueryResource;

    @GetMapping("/typeList")
    public ApiResponse<List<ResourcePO>> queryTypeList(@RequestParam(required = false) String platform) {
        return iQueryResource.queryTypeList(platform);
    }

    /**
     * Get a list of resource types - divide by group
     *
     * @return 资源类型列表
     */
    @PostMapping("/groupTypeList")
    public ApiResponse<List<ResourceGroupTypeVO>> queryGroupTypeList(@RequestBody QueryGroupTypeListRequest request) {
        return iQueryResource.queryGroupTypeList(request.getPlatformList());
    }

    /**
     * Aggregate query by asset type
     */
    @AuthenticateToken
    @RateLimit(maxRequests = 10, timeWindowSeconds = 60, keyStrategy = KeyStrategy.IP, 
               message = "Too many requests for aggregate list query. Please try again later.")
    @PostMapping("/queryAggregateAssets")
    public ApiResponse<ListVO<ResourceAggByInstanceTypeDTO>> queryAggregateAssets(@RequestBody QueryResourceListRequest req) {
        ResourceDTO resourceDTO = new ResourceDTO();
        BeanUtils.copyProperties(req, resourceDTO);
        resourceDTO.setResourceTypeList(ListUtils.setList(req.getResourceTypeList()));
        return iQueryResource.queryAggregateAssets(resourceDTO);
    }

    /**
     * Multi-tenant division query asset list
     */
    @RateLimit(maxRequests = 10, timeWindowSeconds = 60, keyStrategy = KeyStrategy.IP,
            message = "Too many requests for list query. Please try again later.")
    @AuthenticateToken
    @PostMapping("/queryResourceList")
    public ApiResponse<ListVO<ResourceInstanceVO>> queryResourceList(@RequestBody QueryResourceListRequest req) {
        PreventingSQLJoint.checkSortParamField(req.getSortParam(),
                Arrays.asList("gmt_create", "gmt_modified"));
        PreventingSQLJoint.checkSortTypeField(req.getSortType());

        return iQueryResource.queryResourceList(req);
    }

    /**
     * Query asset details
     */
    @AuthenticateToken
    @PostMapping("/queryResourceDetail")
    public ApiResponse<ResourceInstanceVO> queryResourceDetail(@RequestBody @Validated QueryResourceDetailRequest req, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return new ApiResponse<>(bindingResult);
        }
        ResourceInstanceVO resourceInstanceVO = iQueryResource.queryResourceDetail(req.getId());
        return new ApiResponse<>(resourceInstanceVO);
    }

    /**
     * Querying example data for assets
     */
    @PostMapping("/queryResourceExampleData")
    public ApiResponse<Object> queryResourceExampleData(
            @RequestBody @Validated QueryResourceExampleDataRequest queryResourceExampleDataRequest,
            BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        for (LinkDataParam linkedData : queryResourceExampleDataRequest.getLinkedDataList()) {
            if (AssociativeMode.getAssociativeMode(linkedData.getAssociativeMode()) == null) {
                throw new IllegalArgumentException("参数异常");
            }

            if (!linkedData.getAssociativeMode().equals(AssociativeMode.MANY_TO_ONE.getName())
                    && (StringUtils.isBlank(linkedData.getLinkedKey1())
                    || StringUtils.isBlank(linkedData.getLinkedKey2()))) {
                throw new IllegalArgumentException("只有当关联模式为「无关联字段」时，主资产关联字段与关联资产关联字段可以为空");
            }
        }

        return iQueryResource.queryResourceExampleData(queryResourceExampleDataRequest);
    }

    /**
     * Query the number of asset-related risks and improve query speed
     */
    @PostMapping("/queryResourceRiskQuantity")
    public ApiResponse<List<ResourceRiskCountVO>> queryResourceRiskQuantity(@Validated @RequestBody IdListRequest idListRequest, BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }

        return iQueryResource.queryResourceRiskQuantity(idListRequest);
    }
}

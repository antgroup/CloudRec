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
package com.alipay.application.service.system;


import com.alipay.application.share.request.openapi.QueryResourceRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListScrollPageVO;
import com.alipay.application.share.vo.account.CloudAccountVO;
import com.alipay.application.share.vo.resource.ResourceInstanceVO;
import com.alipay.application.share.vo.rule.RuleScanResultVO;
import com.alipay.application.share.vo.rule.RuleVO;
import com.alipay.common.exception.BizException;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.dto.IQueryResourceDTO;
import com.alipay.dao.dto.QueryScanResultDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.CloudResourceInstancePO;
import com.alipay.dao.po.RulePO;
import com.alipay.dao.po.RuleScanResultPO;
import jakarta.annotation.Resource;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/*
 *@title OpenApiService
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/1/6 11:26
 */
@Service
public class OpenApiService {

    @Resource
    private OpenApiAuthMapper openApiAuthMapper;
    @Resource
    public TenantMapper tenantMapper;
    @Resource
    private RuleScanResultMapper ruleScanResultMapper;
    @Resource
    private RuleMapper ruleMapper;
    @Resource
    private CloudAccountMapper cloudAccountMapper;
    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;


    public ApiResponse<ListScrollPageVO<RuleScanResultVO>> queryScanResult(QueryScanResultDTO dto) {
        if (Strings.isNotBlank(dto.getRuleCode())) {
            RulePO rulePO = ruleMapper.findOne(dto.getRuleCode());
            if (Objects.isNull(rulePO)) {
                throw new BizException("The rules do not exist");
            }
            dto.setRuleId(rulePO.getId());
        }
        ListScrollPageVO<RuleScanResultVO> listVO = new ListScrollPageVO<>();
        List<RuleScanResultPO> ruleScanResultPOS = ruleScanResultMapper.findListWithScrollId(dto);
        if (Objects.isNull(ruleScanResultPOS)) {
            return new ApiResponse<>(listVO);
        }

        if (ruleScanResultPOS.size() == dto.getLimit()) {
            listVO.setScrollId(String.valueOf(ruleScanResultPOS.get(ruleScanResultPOS.size() - 1).getId()));
        }

        List<RuleScanResultVO> list = ruleScanResultPOS.stream().map(RuleScanResultVO::buildList).toList();
        listVO.setData(list);
        listVO.setTotal(list.size());
        return new ApiResponse<>(listVO);
    }

    public ApiResponse<RuleVO> queryRuleDetail(String ruleCode) {
        RulePO rulePO = ruleMapper.findOne(ruleCode);
        if (Objects.isNull(rulePO)) {
            throw new BizException("rule Code does not exist");
        }

        return new ApiResponse<>(RuleVO.build(rulePO));
    }

    public ApiResponse<CloudAccountVO> queryAccountDetail(String cloudAccountId) {
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(cloudAccountId);
        if (Objects.isNull(cloudAccountPO)) {
            throw new BizException("cloudAccountId does not exist");
        }
        return new ApiResponse<>(CloudAccountVO.build(cloudAccountPO));
    }

    public ApiResponse<List<CloudAccountVO>> queryCloudAccountList(String platform) {
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().platform(platform).build();
        List<CloudAccountPO> list = cloudAccountMapper.findList(cloudAccountDTO);
        return new ApiResponse<>(list.stream().map(CloudAccountVO::buildEasy).collect(Collectors.toList()));
    }

    public ApiResponse<ListScrollPageVO<ResourceInstanceVO>> queryResourceList(QueryResourceRequest req) {
        IQueryResourceDTO param = IQueryResourceDTO.builder()
                .tenantId(req.getTenantId())
                .resourceId(req.getResourceId())
                .resourceType(req.getResourceType())
                .cloudAccountId(req.getCloudAccountId())
                .platform(req.getPlatform())
                .scrollId(StringUtils.isNotBlank(req.getScrollId()) ? Long.valueOf(req.getScrollId()) : null)
                .size(req.getLimit())
                .build();

        ListScrollPageVO<ResourceInstanceVO> listVO = new ListScrollPageVO<>();
        List<CloudResourceInstancePO> list = cloudResourceInstanceMapper.findByCondWithScrollId(param);
        if (list.size() == param.getSize()) {
            listVO.setScrollId(String.valueOf(list.get(list.size() - 1).getId()));
        }

        List<ResourceInstanceVO> collect = list.stream().map(ResourceInstanceVO::build).toList();
        listVO.setData(collect);
        listVO.setTotal(collect.size());

        return new ApiResponse<>(listVO);
    }
}

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
package com.alipay.application.service.statistics.job;

import com.alibaba.fastjson.JSON;
import com.alipay.application.service.resource.IQueryResource;
import com.alipay.application.service.resource.enums.IdentitySecurityConfig;
import com.alipay.application.service.resource.identitySecurity.AliRamUserResourceParse;
import com.alipay.application.service.resource.identitySecurity.GCPServiceAccountParse;
import com.alipay.application.service.resource.identitySecurity.HuaweiIamUserResourceParse;
import com.alipay.application.service.resource.identitySecurity.KsyunIamUserResourceParse;
import com.alipay.application.service.risk.RiskService;
import com.alipay.application.service.rule.enums.RuleType;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleScanResultVO;
import com.alipay.common.enums.Status;
import com.alipay.common.utils.DateUtil;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.context.UserInfoDTO;
import com.alipay.dao.dto.QueryScanResultDTO;
import com.alipay.dao.dto.RuleDTO;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.mapper.IdentitySecurityMapper;
import com.alipay.dao.mapper.RuleMapper;
import com.alipay.dao.mapper.RuleScanResultMapper;
import com.alipay.dao.mapper.RuleTypeMapper;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Date: 2025/4/17
 * Author: lz
 * desc: 解析云资产数据
 */
@Slf4j
@Component
public class ParseCloudResourceDataJob {

    @Resource
    private AliRamUserResourceParse aliRamUserResourceParse;

    @Resource
    private GCPServiceAccountParse gcpServiceAccountParse;

    @Resource
    private HuaweiIamUserResourceParse huaweiIamUserResourceParse;

    @Resource
    private KsyunIamUserResourceParse ksyunIamUserResourceParse;

	@Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private RuleTypeMapper ruleTypeMapper;

    @Resource
    private RiskService riskService;

    @Resource
    private IdentitySecurityMapper identitySecurityMapper;

    @Resource
    private RuleMapper ruleMapper;

    @Resource
    private IQueryResource iQueryResource;

    public void parseData() {
        //清理历史数据
        identitySecurityMapper.deleteAll();
        //获取指定资产数据
        for (IdentitySecurityConfig config : IdentitySecurityConfig.values()) {

            Map<String, List<RuleScanResultPO>> ruleScanResultVOMap = new HashMap<>();
            List<Long> ruleIds = queryAllRuleId(config);
            for (Long ruleId : ruleIds) {
                List<RuleScanResultPO> ruleScanResultPOList = queryAllRiskByRuleId(config, ruleId);
                for (RuleScanResultPO item : ruleScanResultPOList) {
                    ruleScanResultVOMap.computeIfAbsent(item.getResourceId() + "&" + item.getCloudAccountId()
                            + "&" + item.getResourceType() + "&" + item.getPlatform(), k -> new ArrayList<>()).add(item);
                }
            }
//            List<RuleScanResultPO> allRuleScanResultPOList = queryAllRisk(config);
//            log.info("ParseCloudResourceDataJob queryAllRuleScanResult , platform:{},resourceType:{},size:{}", config.getPlatformType(), config.getResourceType(), allRuleScanResultPOList.size());
//
//            Map<String, List<RuleScanResultPO>> ruleScanResultVOMap = allRuleScanResultPOList.stream().
//                    collect(Collectors.groupingBy(vo -> vo.getResourceId() + "&" + vo.getCloudAccountId()
//                            + "&" + vo.getResourceType() + "&" + vo.getPlatform()));

            List<IdentitySecurityPO> identitySecurityPOList = new ArrayList<>();

            for (String key : ruleScanResultVOMap.keySet()) {
                List<RuleScanResultPO> ruleScanResultPOList = ruleScanResultVOMap.get(key);
                IdentitySecurityPO identitySecurityPO = buildIdentitySecurityParam(config, key, ruleScanResultPOList);
                if (Objects.isNull(identitySecurityPO)) {
                    continue;
                }
                identitySecurityPOList.add(identitySecurityPO);
                if (identitySecurityPOList.size() == 100) {
                    identitySecurityMapper.insertBatch(identitySecurityPOList);
                    identitySecurityPOList.clear();
                }
            }
            if (!identitySecurityPOList.isEmpty()) {
                // 批量写入剩余数据
                identitySecurityMapper.insertBatch(identitySecurityPOList);
            }
        }
    }

    private IdentitySecurityPO buildIdentitySecurityParam(IdentitySecurityConfig config, String key, List<RuleScanResultPO> ruleScanResultList) {
        log.info("ParseCloudResourceDataJob parseData key:{}", key);
        String[] keys = key.split("&");
        String resourceId = keys[0];
        String cloudAccountId = keys[1];
        String resourceType = keys[2];
        String platform = keys[3];

        IdentitySecurityPO identitySecurityPO = new IdentitySecurityPO();
        identitySecurityPO.setGmtCreate(new Date());
        identitySecurityPO.setGmtModified(new Date());
        identitySecurityPO.setResourceId(resourceId);
        identitySecurityPO.setCloudAccountId(cloudAccountId);
        identitySecurityPO.setPlatform(platform);
        identitySecurityPO.setResourceType(resourceType);

        Set<String> ruleIdSet = ruleScanResultList.stream()
                .map(RuleScanResultPO::getRuleId)
                .map(String::valueOf)
                .collect(Collectors.toSet());
        String ruleIds = String.join(",", ruleIdSet);
        identitySecurityPO.setRuleIds(ruleIds);

        CloudResourceInstancePO cloudResourceInstancePO = iQueryResource.query(platform, resourceType, cloudAccountId, resourceId);
        if (Objects.isNull(cloudResourceInstancePO)) {
            log.info("ParseCloudResourceDataJob parseData cloudResourceInstancePO is null, key:{}, resourceId:{}, cloudAccountId:{}, resourceType:{}, platform:{}", key, resourceId, cloudAccountId, resourceType, platform);
            return null;
        }
        String resourceInstance = cloudResourceInstancePO.getInstance();

        identitySecurityPO.setInstance(resourceInstance);
        if (Objects.equals(config, IdentitySecurityConfig.ALI_CLOUD_RAM_User)) {
            aliRamUserResourceParse.parse(identitySecurityPO, resourceInstance);
            identitySecurityPO.setTags(JSON.toJSONString(aliRamUserResourceParse.parseTags(resourceInstance, ruleIds, cloudAccountId, resourceId)));
        }
        if (Objects.equals(config, IdentitySecurityConfig.GCP_IAM_ServiceAccount)) {
            gcpServiceAccountParse.parse(identitySecurityPO, resourceInstance);
        }
        if (Objects.equals(config, IdentitySecurityConfig.HUAWEI_CLOUD_IAM_User)) {
            huaweiIamUserResourceParse.parse(identitySecurityPO, resourceInstance);
        }
        if (Objects.equals(config, IdentitySecurityConfig.KINGSOFT_CLOUD_IAM_User)) {
            ksyunIamUserResourceParse.parse(identitySecurityPO, resourceInstance);
        }
        return identitySecurityPO;
    }

    private List<Long> queryAllRuleId(IdentitySecurityConfig config) {
        RuleTypePO ruleTypePO = ruleTypeMapper.findByTypeName(RuleType.identity_security.getRuleType());
        RuleDTO ruleDTO = RuleDTO.builder().build();
        ruleDTO.setSize(100);
        ruleDTO.setResourceType(config.getResourceType());
        ruleDTO.setStatus(Status.valid.name());
        ruleDTO.setRuleTypeIdList(Arrays.asList(ruleTypePO.getId()));
        List<RulePO> list = ruleMapper.findSortList(ruleDTO);
        List<Long> ruleIds = new ArrayList<>();
        if (!CollectionUtils.isEmpty(list)) {
            ruleIds = list.stream().map(RulePO::getId).collect(Collectors.toList());
        }
        return ruleIds;
    }

    private List<RuleScanResultPO> queryAllRiskByRuleId(IdentitySecurityConfig config, Long ruleId) {
        QueryScanResultDTO dto = new QueryScanResultDTO();
        dto.setPlatform(config.getPlatformType());
        dto.setRuleId(ruleId);
        dto.setResourceType(config.getResourceType());
        dto.setLimit(200);
        List<RuleScanResultPO> ruleScanResultPOList = new ArrayList<>();
        String scrollId = null;
        while (true) {
            dto.setScrollId(scrollId);
            List<RuleScanResultPO> listWithScrollId = ruleScanResultMapper.findBaseInfoWithScrollId(dto);
            if (CollectionUtils.isEmpty(listWithScrollId)) {
                break;
            }
            ruleScanResultPOList.addAll(listWithScrollId);
            scrollId = listWithScrollId.get(listWithScrollId.size() - 1).getId().toString();
        }
        return ruleScanResultPOList;
    }


    private List<RuleScanResultPO> queryAllRisk(IdentitySecurityConfig config) {
        RuleTypePO ruleTypePO = ruleTypeMapper.findByTypeName(RuleType.identity_security.getRuleType());
        RuleDTO ruleDTO = RuleDTO.builder().build();
        ruleDTO.setResourceType(config.getResourceType());
        ruleDTO.setStatus(Status.valid.name());
        ruleDTO.setRuleTypeIdList(Arrays.asList(ruleTypePO.getId()));
        ruleDTO.setPlatform(config.getPlatformType());
        ruleDTO.setSize(100);
        List<RulePO> list = ruleMapper.findSortList(ruleDTO);
        List<Long> ruleIds = new ArrayList<>();
        if (!CollectionUtils.isEmpty(list)) {
            ruleIds = list.stream().map(RulePO::getId).collect(Collectors.toList());
        }
        String gmtModifiedStart = DateUtil.dateToString(DateUtil.getYesterdayStartTime(), DateUtil.YYYY_MM_DD_HH_MM_SS);
        String gmtModifiedEnd = DateUtil.dateToString(DateUtil.getYesterdayEndTime(), DateUtil.YYYY_MM_DD_HH_MM_SS);
        QueryScanResultDTO dto = new QueryScanResultDTO();
        dto.setPlatform(config.getPlatformType());
        dto.setRuleIdList(ruleIds);
        dto.setResourceType(config.getResourceType());
        dto.setGmtModifiedStart(gmtModifiedStart);
        dto.setGmtModifiedEnd(gmtModifiedEnd);

        String scrollId = null;
        List<RuleScanResultPO> ruleScanResultPOList = new ArrayList<>();
        while (true) {
            dto.setScrollId(scrollId);
            List<RuleScanResultPO> listWithScrollId = ruleScanResultMapper.findListWithScrollId(dto);
            if (CollectionUtils.isEmpty(listWithScrollId)) {
                break;
            }
            ruleScanResultPOList.addAll(listWithScrollId);
            scrollId = listWithScrollId.get(listWithScrollId.size() - 1).getId().toString();
        }
        return ruleScanResultPOList;
    }


    private List<RuleScanResultVO> queryAllRuleScanResult(IdentitySecurityConfig config) {
        RuleTypePO ruleTypePO = ruleTypeMapper.findByTypeName(RuleType.identity_security.getRuleType());
        RuleDTO ruleDTO = RuleDTO.builder().build();
        ruleDTO.setPlatform(config.getPlatformType());
        ruleDTO.setResourceType(config.getResourceType());
        ruleDTO.setStatus(Status.valid.name());
        ruleDTO.setRuleTypeIdList(Arrays.asList(ruleTypePO.getId()));
        ruleDTO.setSize(100);
        List<RulePO> list = ruleMapper.findSortList(ruleDTO);
        List<Long> ruleIds = new ArrayList<>();
        if (!CollectionUtils.isEmpty(list)) {
            ruleIds = list.stream().map(RulePO::getId).collect(Collectors.toList());
        }

        RuleScanResultDTO ruleScanResultDTO = RuleScanResultDTO.builder()
                .platform(config.getPlatformType())
                .resourceType(config.getResourceType())
                .ruleTypeIdList(Arrays.asList(ruleTypePO.getId()))
                .ruleIdList(ruleIds)
                .build();


        List<RuleScanResultVO> resultList = new ArrayList<>();
        Integer page = 1;
        ruleScanResultDTO.setSize(200);
        //伪代码
        UserInfoContext.setCurrentUser(new UserInfoDTO());
        while (true) {
            ruleScanResultDTO.setPage(page);
            ApiResponse<ListVO<RuleScanResultVO>> listVOApiResponse = riskService.queryRiskList(ruleScanResultDTO);
            ListVO<RuleScanResultVO> ruleScanResultVOListVO = listVOApiResponse.getContent();
            if (Objects.isNull(ruleScanResultVOListVO) || CollectionUtils.isEmpty(ruleScanResultVOListVO.getData())) {
                break;
            }
            resultList.addAll(ruleScanResultVOListVO.getData());
            page++;
        }
        log.info("ParseCloudResourceDataJob queryAllRuleScanResult size:{}", resultList.size());
        return resultList;
    }


}

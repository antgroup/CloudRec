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
package com.alipay.application.service.resource.identitySecurity;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.alipay.application.service.common.Notify;
import com.alipay.application.service.common.utils.CacheUtil;
import com.alipay.application.service.common.utils.DbCacheUtil;
import com.alipay.application.service.resource.enums.IdentitySecurityConfig;
import com.alipay.application.service.resource.enums.IdentityTagConfig;
import com.alipay.application.service.resource.identitySecurity.model.ResourceAccessInfoDTO;
import com.alipay.application.service.resource.identitySecurity.model.ResourcePolicyInfoDTO;
import com.alipay.application.service.resource.identitySecurity.model.ResourceUserInfoDTO;
import com.alipay.application.service.rule.domain.repo.RuleRepository;
import com.alipay.application.service.rule.enums.RuleType;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.application.share.request.resource.QueryIdentityCardRequest;
import com.alipay.application.share.request.resource.QueryIdentityRuleRequest;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.resource.IdentityCardVO;
import com.alipay.application.share.vo.resource.IdentitySecurityRiskInfoVO;
import com.alipay.application.share.vo.resource.IdentitySecurityVO;
import com.alipay.common.enums.PlatformType;
import com.alipay.common.enums.Status;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.dto.IdentitySecurityDTO;
import com.alipay.dao.dto.RuleDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Date: 2025/4/23
 * Author: lz
 */
@Service
public class IdentitySecurityServiceImpl implements IdentitySecurityService {
    @Resource
    private IdentitySecurityMapper identitySecurityMapper;
    @Resource
    private RuleMapper ruleMapper;
    @Resource
    private PlatformMapper platformMapper;
    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;
    @Resource
    private RuleTypeMapper ruleTypeMapper;
    @Resource
    private RuleRepository ruleRepository;
    @Resource
    private TenantRepository tenantRepository;

    @Resource
    private DbCacheUtil dbCacheUtil;

    private static final String dbCacheKey = "idententy::query_identity_card_list";


    @Override
    public List<String> getTagList() {
        return Arrays.stream(IdentityTagConfig.values())
                .map(IdentityTagConfig::getTagName)
                .collect(Collectors.toList());
    }

    @Override
    public ListVO<IdentitySecurityVO> queryIdentitySecurityList(QueryIdentityRuleRequest request) {

        if (StringUtils.isBlank(request.getRuleIds()) && StringUtils.isBlank(request.getPlatform())) {
            throw new RuntimeException("ruleIds and platform cannot be empty at the same time");
        }

        IdentitySecurityDTO dto = new IdentitySecurityDTO();
        BeanUtils.copyProperties(request, dto);
        if (StringUtils.isNotBlank(request.getRuleIds())) {
            dto.setRuleIds(Arrays.asList(StringUtils.split(request.getRuleIds(), ",")));
        }

        if (StringUtils.isNotBlank(request.getTags())) {
            dto.setTags(Arrays.asList(StringUtils.split(request.getTags(), ",")));
        }

        if (StringUtils.isNotBlank(request.getAccessKeyIds())) {
            dto.setAccessKeyIdList(Arrays.asList(StringUtils.split(request.getAccessKeyIds(), ",")));
        }

        ListVO<IdentitySecurityVO> listVO = new ListVO<>();
        int count = identitySecurityMapper.count(dto);
        if (count == 0) {
            return listVO;
        }

        dto.setOffset();
        List<IdentitySecurityPO> identitySecurityPOS = identitySecurityMapper.queryList(dto);
        if (!CollectionUtils.isEmpty(identitySecurityPOS)) {
            List<IdentitySecurityVO> collect = identitySecurityPOS.stream().map(this::coverToVO).collect(Collectors.toList());
            listVO.setData(collect);
        }
        listVO.setTotal(count);
        return listVO;
    }

    @Override
    public IdentitySecurityVO queryIdentitySecurityDetail(Long id) {
        IdentitySecurityPO identitySecurityPO = identitySecurityMapper.selectByPrimaryKey(id);
        if (Objects.isNull(identitySecurityPO)) {
            return new IdentitySecurityVO();
        }
        return coverToVO(identitySecurityPO);
    }

    private IdentitySecurityVO coverToVO(IdentitySecurityPO identitySecurityPO) {
        IdentitySecurityVO identitySecurityVO = new IdentitySecurityVO();
        BeanUtils.copyProperties(identitySecurityPO, identitySecurityVO);
        CloudResourceInstancePO cloudResourceInstancePO = cloudResourceInstanceMapper.findOne(identitySecurityVO.getPlatform(), identitySecurityPO.getResourceType(), identitySecurityPO.getCloudAccountId(), identitySecurityPO.getResourceId());
        if (Objects.nonNull(cloudResourceInstancePO)) {
            identitySecurityVO.setResourceName(cloudResourceInstancePO.getResourceName());
        }
        identitySecurityVO.setUserInfo(JSON.parseObject(identitySecurityPO.getUserInfo(), ResourceUserInfoDTO.class));
        identitySecurityVO.setAccessInfos(JSON.parseArray(identitySecurityPO.getAccessInfos(), ResourceAccessInfoDTO.class));
        identitySecurityVO.setPolicies(JSON.parseArray(identitySecurityPO.getPolicies(), ResourcePolicyInfoDTO.class));
        if (StringUtils.isNotBlank(identitySecurityPO.getTags())) {
            identitySecurityVO.setTags(JSON.parseObject(identitySecurityPO.getTags(), List.class));
        }
        return identitySecurityVO;
    }

    @Override
    public List<IdentitySecurityRiskInfoVO> queryRiskInfo(QueryIdentityRuleRequest request) {
        List<IdentitySecurityRiskInfoVO> riskInfoVOList = new ArrayList<>();
        if (Objects.isNull(request.getId())) {
            return riskInfoVOList;
        }
        IdentitySecurityPO identitySecurityPO = identitySecurityMapper.selectByPrimaryKey(request.getId());
        if (Objects.isNull(identitySecurityPO)) {
            return riskInfoVOList;
        }

        List<Long> ruleIdList = Arrays.stream(identitySecurityPO.getRuleIds().split(","))
                .map(Long::valueOf)
                .collect(Collectors.toList());
        RuleDTO ruleDTO = RuleDTO.builder()
                .ruleIdList(ruleIdList)
                .build();
        List<RulePO> ruleList = ruleMapper.findList(ruleDTO);

        for (RulePO rulePO : ruleList) {
            IdentitySecurityRiskInfoVO riskInfoVO = new IdentitySecurityRiskInfoVO();
            riskInfoVO.setRuleName(rulePO.getRuleName());
            riskInfoVO.setRuleDesc(rulePO.getRuleDesc());
            String context = Notify.parseTemplate(rulePO.getContext(), identitySecurityPO.getInstance());
            riskInfoVO.setContext(context);
            riskInfoVOList.add(riskInfoVO);
        }
        return riskInfoVOList;
    }

    @Override
    public List<PlatformPO> getPlatformList() {
        List<PlatformPO> res = new ArrayList<>();
        List<String> platformList = List.of(PlatformType.Enum.ALI_CLOUD, PlatformType.Enum.GCP, PlatformType.HUAWEI_CLOUD.getPlatform(), PlatformType.Enum.KINGSOFT_CLOUD);
        for (String platform : platformList) {
            PlatformPO platformPO = platformMapper.findByPlatform(platform);
            if (platformPO != null) {
                res.add(platformPO);
            }
        }

        return res;
    }


    @Override
    public List<IdentityCardVO> queryIdentityCardListWithRulds(QueryIdentityCardRequest request) {
        String key = CacheUtil.buildKey(dbCacheKey,
                UserInfoContext.getCurrentUser().getUserTenantId(),
                request.getPlatformList(),
                request.getPage(),
                request.getSize());

        DbCachePO dbCachePO = dbCacheUtil.get(key);
        if (dbCachePO != null) {
            return JSON.parseObject(dbCachePO.getValue(), new TypeReference<>() {
            });
        }

        RuleDTO ruleDTO = RuleDTO.builder().build();
        BeanUtils.copyProperties(request, ruleDTO);

        RuleTypePO ruleTypePO = ruleTypeMapper.findByTypeName(RuleType.identity_security.getRuleType());
        ruleDTO.setRuleTypeIdList(Collections.singletonList(ruleTypePO.getId()));
        ruleDTO.setStatus(Status.valid.name());
        ruleDTO.setResourceTypeList(IdentitySecurityConfig.getResourceTypeByPlatformList(request.getPlatformList()));
        ruleDTO.setSize(100);
        List<RulePO> list = ruleMapper.findSortList(ruleDTO);


        List<IdentityCardVO> identityCardVOList = new ArrayList<>();
        for (RulePO rulePO : list) {
            boolean defaultRule = tenantRepository.isDefaultRule(rulePO.getRuleCode());
            if (!defaultRule) {
                continue;
            }

            IdentitySecurityDTO identitySecurityDTO = new IdentitySecurityDTO();
            identitySecurityDTO.setRuleId(String.valueOf(rulePO.getId()));
            identitySecurityDTO.setPlatformList(request.getPlatformList());
            int count = identitySecurityMapper.countRuId(identitySecurityDTO);

            IdentityCardVO identityCardVO = new IdentityCardVO();
            identityCardVO.setRuleId(rulePO.getId());
            identityCardVO.setRuleCode(rulePO.getRuleCode());
            identityCardVO.setRuleName(rulePO.getRuleName());
            identityCardVO.setPlatform(rulePO.getPlatform());
            identityCardVO.setRiskLevel(rulePO.getRiskLevel());
            identityCardVO.setUserCount(count);
            identityCardVOList.add(identityCardVO);
        }

        dbCacheUtil.put(key, identityCardVOList);

        return identityCardVOList;
    }
}

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
package com.alipay.application.service.rule;/*
 *@title RuleServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/5 17:02
 */

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.alipay.application.service.common.utils.CacheUtil;
import com.alipay.application.service.common.utils.DbCacheUtil;
import com.alipay.application.service.rule.domain.repo.RuleGroupRepository;
import com.alipay.application.service.rule.enums.RuleType;
import com.alipay.application.service.rule.exposed.GroupJoinService;
import com.alipay.application.share.request.base.IdRequest;
import com.alipay.application.share.request.rule.ChangeStatusRequest;
import com.alipay.application.share.request.rule.ListRuleRequest;
import com.alipay.application.share.request.rule.RegoRequest;
import com.alipay.application.share.request.rule.SaveRuleRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleTypeVO;
import com.alipay.application.share.vo.rule.RuleVO;
import com.alipay.common.enums.Status;
import com.alipay.common.utils.ListUtils;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.dto.RuleDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;

@Slf4j
@Service
public class RuleServiceImpl implements RuleService {

    @Resource
    private RuleMapper ruleMapper;
    @Resource
    private GroupJoinService groupJoinService;
    @Resource
    private RuleRegoMapper ruleRegoMapper;
    @Resource
    private RegoService regoService;
    @Resource
    private RuleTypeMapper ruleTypeMapper;
    @Resource
    private RuleTypeRelMapper ruleTypeRelMapper;
    @Resource
    private RuleScanResultMapper ruleScanResultMapper;
    @Resource
    private GlobalVariableConfigRuleRelMapper globalVariableConfigRuleRelMapper;
    @Resource
    private RuleGroupRepository ruleGroupRepository;
    @Resource
    private DbCacheUtil dbCacheUtil;

    public static final String cacheKey = "rule::query_rule_list";

    @Transactional(rollbackFor = Exception.class)
    @Override
    public synchronized ApiResponse<String> saveRule(SaveRuleRequest request) throws IOException {
        if (request.getId() == null) {
            RulePO rulePO = ruleMapper.findOneByCond(request.getPlatform(), request.getRuleName());
            if (rulePO != null) {
                return new ApiResponse<>(ApiResponse.FAIL.getCode(), "The rule name already exists");
            }
        }

        RulePO rulePO = new RulePO();
        BeanUtils.copyProperties(request, rulePO);

        rulePO.setResourceType(request.getResourceType().get(1));
        if (request.getLinkedDataList() != null && !request.getLinkedDataList().isEmpty()) {
            rulePO.setLinkedDataList(JSON.toJSONString(request.getLinkedDataList()));
        }


        // 1. Save rule
        if (rulePO.getId() == null) {
            rulePO.setUserId(UserInfoContext.getCurrentUser().getUserId());
            rulePO.setStatus(Status.valid.name());
            rulePO.setRuleCode(generateRuleCode(rulePO.getPlatform(), rulePO.getResourceType()));
            rulePO.setGmtCreate(new Date());
            rulePO.setGmtModified(new Date());
            ruleMapper.insertSelective(rulePO);
        } else {
            rulePO.setGmtModified(new Date());
            ruleMapper.updateByPrimaryKeySelective(rulePO);
        }

        // Association rule group
        if (CollectionUtils.isNotEmpty(request.getRuleGroupIdList())) {
            ruleGroupRepository.join(request.getRuleGroupIdList(), rulePO.getId());
        }

        groupJoinService.joinDefaultGroup(rulePO.getId());

        // 2. Save rego rules
        if (request.getRuleRego() != null) {
            RegoRequest req = new RegoRequest();
            req.setRuleId(rulePO.getId());
            req.setRuleRego(request.getRuleRego());
            regoService.saveRego(req);
        }

        // 3. Save the relationship between rules and rule types
        ruleTypeRelMapper.del(rulePO.getId());
        List<Long> ruleTypeIdList = ListUtils.setList(request.getRuleTypeIdList());
        for (Long ruleTypeId : ruleTypeIdList) {
            RuleTypeRelPO ruleTypeRelPO = new RuleTypeRelPO();
            ruleTypeRelPO.setRuleTypeId(ruleTypeId);
            ruleTypeRelPO.setRuleId(rulePO.getId());
            ruleTypeRelMapper.insertSelective(ruleTypeRelPO);
        }

        // 4. Save the mapping relationship between rules and global variables
        globalVariableConfigRuleRelMapper.delByRuleId(rulePO.getId());
        if (request.getGlobalVariableConfigIdList() != null) {
            for (Long id : request.getGlobalVariableConfigIdList()) {
                GlobalVariableConfigRuleRelPO globalVariableConfigRuleRelPO = new GlobalVariableConfigRuleRelPO();
                globalVariableConfigRuleRelPO.setGlobalVariableConfigId(id);
                globalVariableConfigRuleRelPO.setRuleId(rulePO.getId());
                globalVariableConfigRuleRelMapper.insertSelective(globalVariableConfigRuleRelPO);
            }
        }

        dbCacheUtil.clear(cacheKey);

        return new ApiResponse<>(String.valueOf(rulePO.getId()));
    }


    @Override
    public ApiResponse<ListVO<RuleVO>> queryRuleList(ListRuleRequest request) {
        boolean needCache = false;
        String key = CacheUtil.buildKey(cacheKey, UserInfoContext.getCurrentUser().getUserTenantId(), request.getPage(), request.getSize(),
                request.getSortParam(), request.getSortType());
        if (ListUtils.isEmpty(request.getPlatformList())
                && ListUtils.isEmpty(request.getRuleTypeIdList())
                && ListUtils.isEmpty(request.getResourceTypeList())
                && StringUtils.isEmpty(request.getStatus())
                && ListUtils.isEmpty(request.getRuleCodeList())
                && ListUtils.isEmpty(request.getRiskLevelList())
                && ListUtils.isEmpty(request.getRuleGroupIdList())) {
            needCache = true;
            DbCachePO dbCachePO = dbCacheUtil.get(key);
            if (dbCachePO != null) {
                ListVO<RuleVO> listVO = JSON.parseObject(dbCachePO.getValue(), new TypeReference<>() {
                });
                return new ApiResponse<>(listVO);
            }
        }

        RuleDTO ruleDTO = RuleDTO.builder().build();
        BeanUtils.copyProperties(request, ruleDTO);
        ruleDTO.setResourceTypeList(ListUtils.setList(request.getResourceTypeList()));
        ruleDTO.setRuleTypeIdList(ListUtils.setList(request.getRuleTypeIdList()));
        ruleDTO.setTenantId(UserInfoContext.getCurrentUser().getUserTenantId());

        ListVO<RuleVO> listVO = new ListVO<>();
        int count = ruleMapper.findCount(ruleDTO);
        if (count == 0) {
            return new ApiResponse<>(listVO);
        }

        ruleDTO.setOffset();
        List<RulePO> list = ruleMapper.findSortList(ruleDTO);

        List<RuleVO> collect = list.stream().map(RuleVO::buildEasy).toList();
        listVO.setTotal(count);
        listVO.setData(collect);

        if (needCache) {
            dbCacheUtil.put(key, listVO);
        }

        return new ApiResponse<>(listVO);
    }

    @Transactional(rollbackFor = Exception.class)
    @Override
    public ApiResponse<String> deleteRule(Long id) {
        ruleMapper.deleteByPrimaryKey(id);
        ruleScanResultMapper.deleteByRuleId(id);
        dbCacheUtil.clear(cacheKey);
        return ApiResponse.SUCCESS;
    }

    @Transactional(rollbackFor = Exception.class)
    @Override
    public ApiResponse<String> changeRuleStatus(ChangeStatusRequest changeRuleStatusRequest) {
        ruleMapper.updateStatus(changeRuleStatusRequest.getId(), changeRuleStatusRequest.getStatus());
        dbCacheUtil.clear(cacheKey);
        return ApiResponse.SUCCESS;
    }

    @Transactional(rollbackFor = Exception.class)
    @Override
    public synchronized ApiResponse<String> copyRule(IdRequest idRequest) {
        RulePO rulePO = ruleMapper.selectByPrimaryKey(idRequest.getId());
        if (rulePO == null) {
            return new ApiResponse<>(ApiResponse.FAIL_CODE, "The rules do not exist");
        }

        // save rule
        Long oldRuleId = rulePO.getId();
        rulePO.setId(null);
        rulePO.setRuleName("[" + rulePO.getRuleName() + "]" + "_copy");
        rulePO.setStatus(Status.invalid.name());
        rulePO.setRuleRegoId(rulePO.getRuleRegoId());
        rulePO.setLastScanTime(null);
        rulePO.setUserId(UserInfoContext.getCurrentUser().getUserId());
        rulePO.setRuleCode(generateRuleCode(rulePO.getPlatform(), rulePO.getResourceType()));
        ruleMapper.insertSelective(rulePO);

        // join defaultGroup
        groupJoinService.joinDefaultGroup(rulePO.getId());

        // Create rego rules
        RuleRegoPO ruleRegoPO = ruleRegoMapper.findLatestOne(oldRuleId);
        if (ruleRegoPO != null) {
            ruleRegoPO.setId(null);
            ruleRegoPO.setRuleId(rulePO.getId());
            ruleRegoPO.setUserId(UserInfoContext.getCurrentUser().getUserId());
            ruleRegoPO.setVersion(0);
            ruleRegoPO.setGmtCreate(new Date());
            ruleRegoPO.setGmtModified(new Date());
            ruleRegoMapper.insertSelective(ruleRegoPO);
        }

        // copy rule type relation
        List<RuleTypeRelPO> ruleTypeRelPOS = ruleTypeRelMapper.findByRuleId(oldRuleId);
        List<Long> ruleTypeIdList = ruleTypeRelPOS.stream().map(RuleTypeRelPO::getRuleTypeId).toList();
        for (Long ruleTypeId : ruleTypeIdList) {
            RuleTypeRelPO ruleTypeRelPO = new RuleTypeRelPO();
            ruleTypeRelPO.setRuleTypeId(ruleTypeId);
            ruleTypeRelPO.setRuleId(rulePO.getId());
            ruleTypeRelMapper.insertSelective(ruleTypeRelPO);
        }

        dbCacheUtil.clear(cacheKey);
        return ApiResponse.SUCCESS;
    }

    @Override
    public ApiResponse<RuleVO> queryRuleDetail(IdRequest idRequest) {
        RulePO rulePO = ruleMapper.selectByPrimaryKey(idRequest.getId());
        RuleVO ruleVO = RuleVO.build(rulePO);
        return new ApiResponse<>(ruleVO);
    }

    @Override
    public ApiResponse<List<RuleTypeVO>> queryRuleTypeList() {
        List<RuleTypeVO> list = new ArrayList<>();
        List<RuleTypePO> parentList = ruleTypeMapper.findAllParentTypeList();
        for (RuleTypePO parent : parentList) {
            RuleTypeVO ruleTypeVO = RuleTypeVO.build(parent);
            List<RuleTypePO> childList = ruleTypeMapper.findListByParentId(parent.getId());
            List<RuleTypeVO> childVOList = childList.stream().map(RuleTypeVO::build).toList();
            ruleTypeVO.setChildList(childVOList);
            list.add(ruleTypeVO);
        }

        Locale locale = LocaleContextHolder.getLocale();
        if (!locale.getLanguage().equals(Locale.CHINA.getLanguage())) {
            for (RuleTypeVO ruleTypeVO : list){
                ruleTypeVO.setTypeName(RuleType.getByRuleTypeEn(ruleTypeVO.getTypeName()));
            }
        }

        return new ApiResponse<>(list);
    }

    @Override
    public List<String> queryRuleTypeNameList(Long ruleId) {
        List<RuleTypePO> ruleTypePOList = ruleTypeMapper.findRuleTypeByRuleId(ruleId);
        if (ruleTypePOList == null) {
            return List.of();
        }

        List<String> list = ruleTypePOList.stream().map(e -> {
            String result;
            if (e.getParentId() != null) {
                RuleTypePO ruleTypePO = ruleTypeMapper.selectByPrimaryKey(e.getParentId());
                result = ruleTypePO.getTypeName() + "/" + e.getTypeName();
            } else {
                result = e.getTypeName();
            }

            return result;
        }).toList();

        Locale locale = LocaleContextHolder.getLocale();
        if (!locale.getLanguage().equals(Locale.CHINA.getLanguage())) {
            list = list.stream().map(RuleType::getByRuleTypeEn).toList();
        }

        return list;
    }

    @Override
    public List<String> queryRuleNameList() {
        RuleDTO ruleDTO = RuleDTO.builder().build();
        List<RulePO> rulePOS = ruleMapper.findList(ruleDTO);
        if (rulePOS == null) {
            return List.of();
        }
        return rulePOS.stream().map(RulePO::getRuleName).distinct().toList();
    }

    @Override
    public String generateRuleCode(String platform, String resourceType) {
        // Automatically generate ruleCode ruleCode rules: platform + resource type + date time 202501072243 + 6-digit random number
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmm");
        String dateTime = dateFormat.format(new Date());

        Random random = new Random();
        // Generate random numbers with a range of 100000 to 999999
        int randomNumber = 100000 + random.nextInt(999999);

        String code = platform + "_" + resourceType + "_" + dateTime + "_" + randomNumber;

        RulePO rulePO = ruleMapper.findOne(code);
        if (rulePO == null) {
            return code;
        }
        return generateRuleCode(platform, resourceType);
    }

    @Override
    public List<RuleVO> queryAllRuleList() {
        List<RulePO> all = ruleMapper.findAll();
        return all.stream().map(po -> {
            RuleVO ruleVO = new RuleVO();
            ruleVO.setRuleCode(po.getRuleCode());
            ruleVO.setRuleName(po.getRuleName());
            ruleVO.setPlatform(po.getPlatform());
            ruleVO.setRuleDesc(po.getRuleDesc());
            ruleVO.setId(po.getId());
            return ruleVO;
        }).toList();
    }
}

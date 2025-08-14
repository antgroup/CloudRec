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
package com.alipay.application.share.vo.rule;
/*
 *@title RuleVO
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/5 16:50
 */

import com.alibaba.fastjson.JSON;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.application.service.rule.RuleService;
import com.alipay.application.service.rule.domain.RuleGroup;
import com.alipay.application.service.rule.domain.repo.RuleGroupRepository;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.application.share.request.rule.LinkDataParam;
import com.alipay.common.utils.ListUtils;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.dto.RuleGroupDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import org.springframework.beans.BeanUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

@Data
public class RuleVO {

    private Long id;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtCreate;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtModified;

    /**
     * 最近一次扫描时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date lastScanTime;


    /**
     * 规则名称
     */
    private String ruleName;

    /**
     * 规则组名称
     */
    private List<RuleGroupVO> ruleGroupList;

    /**
     * 风险等级
     */
    private String riskLevel;

    /**
     * 平台
     */
    private String platform;

    /**
     * 资源类型
     */
    private List<String> resourceType;

    /**
     * 资源类型
     */
    private String resourceTypeStr;

    /**
     * 用户id
     */
    private String userId;

    /**
     * 用户名
     */
    private String username;

    /**
     * 规则描述
     */
    private String ruleDesc;

    /**
     * 规则风险数量
     */
    private Integer riskCount;

    /**
     * 规则上下文
     */
    private String context;

    /**
     * 规则建议
     */
    private String advice;

    /**
     * 修复文档链接
     */
    private String link;

    /**
     * 状态
     */
    private String status;

    /**
     * rego 规则
     */
    private String ruleRego;

    /**
     * 是否处于运行状态
     */
    private Integer isRunning;

    /**
     * 规则组id
     */
    private List<String> ruleGroupNameList;

    /**
     * 规则关联的规则类型
     */
    private List<RuleTypeVO> ruleTypeList;

    /**
     * 规则关联的规则类型id列表
     */
    private List<List<Long>> ruleTypeIdList;

    /**
     * 规则关联的规则类型名称列表
     */
    private List<String> ruleTypeNameList;

    /**
     * 关联数据
     */
    private List<LinkDataParam> linkedDataList;

    /**
     * 关联数据描述
     */
    private String linkedDataDesc;

    /**
     * 全局变量配置id列表
     */
    private List<Long> globalVariableConfigIdList;

    /**
     * 规则唯一code
     */
    private String ruleCode;

    /**
     * 当前租户是否选择规则
     */
    private Boolean tenantSelected;

    /**
     * 全局租户是否已选择当前规则
     */
    private Boolean defaultRuleSelected;

    /**
     * 使用中的租户名称列表
     */
    private List<String> selectedTenantNameList;

    private static RuleScanResultMapper ruleScanResultMapper = SpringUtils.getBean(RuleScanResultMapper.class);

    private static RuleGroupRepository ruleGroupRepository = SpringUtils.getBean(RuleGroupRepository.class);

    private static RuleService ruleService = SpringUtils.getApplicationContext().getBean(RuleService.class);

    private static RuleGroupMapper ruleGroupMapper = SpringUtils.getApplicationContext().getBean(RuleGroupMapper.class);

    private static RuleRegoMapper ruleRegoMapper = SpringUtils.getApplicationContext().getBean(RuleRegoMapper.class);

    private static RuleTypeMapper ruleTypeMapper = SpringUtils.getApplicationContext().getBean(RuleTypeMapper.class);

    private static GlobalVariableConfigRuleRelMapper globalVariableConfigRuleRelMapper = SpringUtils.getApplicationContext().getBean(GlobalVariableConfigRuleRelMapper.class);

    private static ResourceMapper resourceMapper = SpringUtils.getApplicationContext().getBean(ResourceMapper.class);

    private static UserMapper userMapper = SpringUtils.getApplicationContext().getBean(UserMapper.class);

    private static TenantRepository tenantRepository = SpringUtils.getApplicationContext().getBean(TenantRepository.class);


    public static RuleVO buildEasy(RulePO rulePO) {
        RuleVO ruleVO = new RuleVO();
        BeanUtils.copyProperties(rulePO, ruleVO);
        ruleVO.setRuleTypeNameList(ruleService.queryRuleTypeNameList(rulePO.getId()));
        List<String> resourceList = queryResource(rulePO.getPlatform(), rulePO.getResourceType());
        if (!resourceList.isEmpty()) {
            ruleVO.setResourceTypeStr(resourceList.get(1));
        } else {
            ruleVO.setResourceTypeStr(rulePO.getResourceType());
        }

        ruleVO.setUsername(queryUserName(rulePO.getUserId()));
        List<RuleGroup> list = ruleGroupRepository.findByRuleId(rulePO.getId());
        if (!list.isEmpty()) {
            ruleVO.setRuleGroupNameList(list.stream().map(RuleGroup::getGroupName).toList());
        }

        ruleVO.setTenantSelected(tenantRepository.isSelected(UserInfoContext.getCurrentUser().getUserTenantId(), rulePO.getRuleCode()));
        ruleVO.setDefaultRuleSelected(tenantRepository.isDefaultRule(rulePO.getRuleCode()));
        ruleVO.setSelectedTenantNameList(tenantRepository.findSelectTenantList(rulePO.getRuleCode()));

        return ruleVO;
    }

    public static RuleVO build(RulePO rulePO) {
        if (rulePO == null) {
            return null;
        }

        // 规则信息
        RuleVO ruleVO = new RuleVO();
        BeanUtils.copyProperties(rulePO, ruleVO);
        List<RuleGroupPO> list = ruleGroupMapper.findList(RuleGroupDTO.builder().ruleIdList(List.of(rulePO.getId())).build());
        if (ListUtils.isNotEmpty(list)) {
            ruleVO.setRuleGroupList(list.stream().map(RuleGroupVO::buildEasy).toList());
        }

        // 查找最新的策略信息
        RuleRegoPO ruleRegoPO = ruleRegoMapper.findLatestOne(rulePO.getId());
        if (ruleRegoPO != null) {
            ruleVO.setRuleRego(ruleRegoPO.getRuleRego());
        }

        // 查询用户信息
        ruleVO.setUsername(queryUserName(rulePO.getUserId()));

        // 查找规则类型信息
        List<RuleTypePO> ruleTypePOList = ruleTypeMapper.findRuleTypeByRuleId(rulePO.getId());
        List<RuleTypeVO> ruleTypeVOList = ruleTypePOList.stream().map(RuleTypeVO::build).toList();
        ruleVO.setRuleTypeList(ruleTypeVOList);

        // 检测是否有父节点，父节点放在第一个元素
        List<List<Long>> ruleTypeIdList = new ArrayList<>();
        for (RuleTypePO ruleTypePO : ruleTypePOList) {
            List<Long> ruleTypeIds = new ArrayList<>();
            if (ruleTypePO.getParentId() != null) {
                // 查询父节点
                RuleTypePO ruleType = ruleTypeMapper.selectByPrimaryKey(ruleTypePO.getParentId());
                ruleTypeIds.add(ruleType.getId());
                ruleTypeIds.add(ruleTypePO.getId());
            } else {
                ruleTypeIds.add(ruleTypePO.getId());
            }
            ruleTypeIdList.add(ruleTypeIds);
        }
        ruleVO.setRuleTypeIdList(ruleTypeIdList);
        ruleVO.setResourceType(queryResource(rulePO.getPlatform(), rulePO.getResourceType()));

        // 关联资产信息
        if (rulePO.getLinkedDataList() != null) {
            ruleVO.setLinkedDataList(JSON.parseArray(rulePO.getLinkedDataList(), LinkDataParam.class));
            StringBuilder desc = new StringBuilder();
            for (LinkDataParam linkedData : ruleVO.getLinkedDataList()) {
                desc.append(linkedData.getResourceType().get(1)).append(" => ").append(linkedData.getNewKeyName())
                        .append("\n");
            }
            ruleVO.setLinkedDataDesc(desc.toString());
        }

        // 全局变量信息
        List<GlobalVariableConfigRuleRelPO> globalVariableConfigRuleRelPOList = globalVariableConfigRuleRelMapper.findByRuleId(rulePO.getId());
        if (!globalVariableConfigRuleRelPOList.isEmpty()) {
            ruleVO.setGlobalVariableConfigIdList(globalVariableConfigRuleRelPOList.stream()
                    .map(GlobalVariableConfigRuleRelPO::getGlobalVariableConfigId).toList());
        }

        ruleVO.setTenantSelected(tenantRepository.isSelected(UserInfoContext.getCurrentUser().getUserTenantId(), rulePO.getRuleCode()));
        return ruleVO;
    }

    private static List<String> queryResource(String platform, String resourceType) {
        ResourcePO resourcePO = resourceMapper.findOne(platform, resourceType);
        if (resourcePO != null) {
            return Arrays.asList(resourcePO.getResourceGroupType(), resourcePO.getResourceType());
        }

        return List.of();
    }

    private static String queryUserName(String userId) {
        if (userId != null) {
            UserPO userPO = userMapper.findOne(userId);
            if (userPO != null) {
                return userPO.getUsername();
            }
        }
        return userId;
    }

}

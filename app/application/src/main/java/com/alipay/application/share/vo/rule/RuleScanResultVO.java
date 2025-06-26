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

import com.alipay.application.service.resource.IQueryResource;
import com.alipay.application.service.common.Notify;
import com.alipay.application.service.resource.task.ResourceMergerTask;
import com.alipay.application.share.request.rule.LinkDataParam;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.common.enums.ResourceGroupType;
import com.alipay.common.utils.ImageUtil;
import com.alipay.dao.mapper.CloudAccountMapper;
import com.alipay.dao.mapper.ResourceMapper;
import com.alipay.dao.mapper.RuleMapper;
import com.alipay.dao.po.*;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;

import java.util.Date;
import java.util.List;

@Slf4j
@Data
public class RuleScanResultVO {

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtCreate;
    /**
     * 最近一次扫描命中
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtModified;

    /**
     * 风险id
     */
    private Long id;

    /**
     * 规则id
     */
    private Long ruleId;

    /**
     * ruleCode
     */
    private String ruleCode;

    /**
     * 云账号id
     */
    private String cloudAccountId;

    /**
     * 账号别名
     */
    private String alias;

    /**
     * 资源id
     */
    private String resourceId;

    /**
     * 资源名称
     */
    private String resourceName;

    /**
     * 更新时间
     */
    private String updateTime;

    /**
     * 平台
     */
    private String platform;

    /**
     * 资产类型
     */
    private String resourceType;

    /**
     * 扫描结果的详细信息
     */
    private String result;

    /**
     * 区域信息
     */
    private String region;

    /**
     * 租户id
     */
    private Long tenantId;

    /**
     * 状态
     */
    private String status;

    /**
     * 规则快照
     */
    private String ruleSnapshoot;

    /**
     * 资产快照
     */
    private String resourceSnapshoot;

    /**
     * 最新的资产数据
     */
    private String resourceInstance;

    /**
     * 忽略的原因类型
     */
    private String ignoreReasonType;

    /**
     * 忽略的原因
     */
    private String ignoreReason;

    /**
     * 当前资源是否存在
     */
    private Boolean resourceExist;

    /**
     * 关联规则的信息
     */
    private RuleVO ruleVO;

    /**
     * 规则类型名称
     */
    private List<String> ruleTypeNameList;

    /**
     * 规则组类型名称
     */
    private String resourceGroupTypeName;

    /**
     * 规则组类型
     */
    private String resourceGroupType;

    /**
     * 规则组的图标
     */
    private String icon;

    /**
     * 风险上下文
     */
    private String context;

    /**
     * 资源状态
     */
    private String resourceStatus;

    public static RuleScanResultVO buildDetail(RuleScanResultPO ruleScanResultPO) {
        if (ruleScanResultPO == null) {
            return null;
        }

        RuleScanResultVO ruleScanResultVO = buildList(ruleScanResultPO);

        // Query the latest asset information
        IQueryResource iQueryResource = SpringUtils.getApplicationContext().getBean(IQueryResource.class);
        CloudResourceInstancePO resourceInstance = iQueryResource.query(ruleScanResultPO.getPlatform(), ruleScanResultPO.getResourceType(), ruleScanResultPO.getCloudAccountId(), ruleScanResultPO.getResourceId());
        if (resourceInstance != null) {
            RuleMapper ruleMapper = SpringUtils.getApplicationContext().getBean(RuleMapper.class);
            RulePO rulePO = ruleMapper.selectByPrimaryKey(ruleScanResultPO.getRuleId());
            List<CloudResourceInstancePO> cloudResourceInstancePOS = ResourceMergerTask.mergeJsonWithTimeOut(LinkDataParam.deserializeList(rulePO.getLinkedDataList()), List.of(resourceInstance), ruleScanResultPO.getCloudAccountId());
            ruleScanResultVO.setResourceInstance(cloudResourceInstancePOS.get(0).getInstance());
        }

        return ruleScanResultVO;
    }


    public static RuleScanResultVO buildList(RuleScanResultPO ruleScanResultPO) {
        if (ruleScanResultPO == null) {
            return null;
        }

        RuleScanResultVO ruleScanResultVO = new RuleScanResultVO();
        BeanUtils.copyProperties(ruleScanResultPO, ruleScanResultVO);

        // Association Rules
        RuleMapper ruleMapper = SpringUtils.getApplicationContext().getBean(RuleMapper.class);
        RulePO rulePO = ruleMapper.selectByPrimaryKey(ruleScanResultPO.getRuleId());
        if (rulePO != null) {
            RuleVO ruleVO = new RuleVO();
            BeanUtils.copyProperties(rulePO, ruleVO);
            ruleScanResultVO.setRuleVO(ruleVO);
            ruleScanResultVO.setRuleCode(rulePO.getRuleCode());

            String context = Notify.parseTemplate(rulePO.getContext(), ruleScanResultPO.getResult());
            ruleScanResultVO.setContext(context);
        }

        // Query resource type
        ResourceMapper resourceMapper = SpringUtils.getApplicationContext().getBean(ResourceMapper.class);
        ResourcePO resourcePO = resourceMapper.findOne(ruleScanResultPO.getPlatform(), ruleScanResultPO.getResourceType());
        if (resourcePO != null) {
            ResourceGroupType resourceGroupType = ResourceGroupType.getByCode(resourcePO.getResourceGroupType());
            ruleScanResultVO.setResourceGroupTypeName(ResourceGroupType.getDescByCode(resourcePO.getResourceGroupType()));
            ruleScanResultVO.setResourceGroupType(resourceGroupType.getCode());
            ruleScanResultVO.setIcon(ImageUtil.ImageToBase64(resourceGroupType.getIcon()));
        }

        // Query account information
        CloudAccountMapper cloudAccountMapper = SpringUtils.getApplicationContext().getBean(CloudAccountMapper.class);
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(ruleScanResultPO.getCloudAccountId());
        if (cloudAccountPO != null) {
            ruleScanResultVO.setAlias(cloudAccountPO.getAlias());
        }


        // Query the latest asset information
        IQueryResource iQueryResource = SpringUtils.getApplicationContext().getBean(IQueryResource.class);
        CloudResourceInstancePO resourceInstance = iQueryResource.query(ruleScanResultPO.getPlatform(), ruleScanResultPO.getResourceType(), ruleScanResultPO.getCloudAccountId(), ruleScanResultPO.getResourceId());
        ruleScanResultVO.setResourceExist(resourceInstance != null);
        if (resourceInstance != null) {
            ruleScanResultVO.setResourceInstance(resourceInstance.getInstance());
        }

        return ruleScanResultVO;
    }
}
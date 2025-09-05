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
package com.alipay.application.service.common;

import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.application.service.risk.engine.Operator;
import com.alipay.common.enums.Status;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.dto.RuleDTO;
import com.alipay.dao.dto.RuleGroupDTO;
import com.alipay.dao.dto.TenantDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.RuleGroupPO;
import com.alipay.dao.po.RulePO;
import com.alipay.dao.po.TenantPO;
import lombok.Data;

import java.util.List;

/*
 *@title SubcriptionConfigType
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/9/10 17:04
 */
public enum SubscriptionConfigType {

    platform("platform", "云平台", List.of(Operator.EQ), null),
    ruleId("ruleId", "规则名称", List.of(Operator.EQ), null),
    ruleGroupId("ruleGroupId", "规则组", List.of(Operator.EQ), null),
    cloudAccountId("cloudAccountId", "云账号", List.of(Operator.EQ), null),
    tenantId("tenantId", "租户", List.of(Operator.EQ), null);

    private String key;

    private String keyName;

    private List<Operator> operatorList;
    private List<KeyValue> value;


    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKeyName() {
        return keyName;
    }

    public void setKeyName(String keyName) {
        this.keyName = keyName;
    }

    public List<Operator> getOperatorList() {
        return operatorList;
    }

    public void setOperatorList(List<Operator> operatorList) {
        this.operatorList = operatorList;
    }

    public List<KeyValue> getValue() {
        return value;
    }

    public void setValue(List<KeyValue> value) {
        this.value = value;
    }

    SubscriptionConfigType(String key, String keyName, List<Operator> operatorList, List<KeyValue> value) {
        this.key = key;
        this.keyName = keyName;
        this.operatorList = operatorList;
        this.value = value;
    }

    public void setOperator(List<Operator> operatorList) {
        this.operatorList = operatorList;
    }

    // 通过静态块初始化需要延迟加载的Bean
    static {
        initData();
    }

    /**
     * 初始化需要延迟加载的Bean
     */
    public static void initData() {
        // 设置云账号初始值
        CloudAccountMapper cloudAccountMapper = SpringUtils.getBean(CloudAccountMapper.class);
        cloudAccountId.setValue(cloudAccountMapper.findList(CloudAccountDTO.builder().build()).stream()
                .map(e -> new KeyValue(e.getCloudAccountId(), e.getCloudAccountId())).toList());

        // 设置规则初始值
        RuleMapper ruleMapper = SpringUtils.getBean(RuleMapper.class);
        RuleDTO ruleDTO = RuleDTO.builder().status(Status.valid.name()).build();
        List<RulePO> rulePOS = ruleMapper.findList(ruleDTO);
        if (rulePOS != null) {
            ruleId.setValue(rulePOS.stream().map(e -> new KeyValue(e.getId(), e.getRuleName())).toList());
        }

        // 设置平台可选数据
        PlatformMapper platformMapper = SpringUtils.getBean(PlatformMapper.class);
        platform.setValue(platformMapper.findAll().stream()
                .map(platformPO -> new KeyValue(platformPO.getPlatform(), platformPO.getPlatformName())).toList());

        // 设置规则组
        RuleGroupMapper ruleGroupMapper = SpringUtils.getBean(RuleGroupMapper.class);
        List<RuleGroupPO> ruleGroupList = ruleGroupMapper.findList(RuleGroupDTO.builder().build());
        if (ruleGroupList != null) {
            ruleGroupId.setValue(ruleGroupList.stream()
                    .map(ruleGroupPO -> new KeyValue(ruleGroupPO.getId(), ruleGroupPO.getGroupName())).toList());
        }

        // 设置租户
        TenantMapper tenantMapper = SpringUtils.getBean(TenantMapper.class);
        List<TenantPO> tenantList = tenantMapper.findList(new TenantDTO());
        if (tenantList != null) {
            tenantId.setValue(tenantList.stream()
                    .map(tenantPO -> new KeyValue(tenantPO.getId(), tenantPO.getTenantName())).toList());
        }
    }

    @Data
    public static class KeyValue {
        private Object valueName;

        private Object value;

        public KeyValue(Object value, Object valueName) {
            this.valueName = valueName;
            this.value = value;
        }
    }
}

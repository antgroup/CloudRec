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
import com.alipay.common.enums.WhitedRuleOperatorEnum;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.mapper.CloudAccountMapper;
import com.alipay.dao.mapper.ResourceMapper;
import lombok.Data;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Date: 2025/3/13
 * Author: lz
 */
public enum WhitedConfigType {

    cloudAccountId("cloudAccountId", "云账号", Arrays.asList(WhitedRuleOperatorEnum.values()), null),
    resourceType("resourceType", "资源类型", Arrays.asList(WhitedRuleOperatorEnum.values()), null),
    resourceId("resourceId", "资源id", Arrays.asList(WhitedRuleOperatorEnum.values()), null),
    resourceName("resourceName", "  资源名称", Arrays.asList(WhitedRuleOperatorEnum.values()), null),
    ip("ip", "ip地址", Arrays.asList(WhitedRuleOperatorEnum.values()), null);


    private String key;
    private String keyName;
    private List<WhitedRuleOperatorEnum> operatorList;
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

    public List<WhitedRuleOperatorEnum> getOperatorList() {
        return operatorList;
    }

    public void setOperatorList(List<WhitedRuleOperatorEnum> operatorList) {
        this.operatorList = operatorList;
    }

    public List<KeyValue> getValue() {
        return value;
    }

    public void setValue(List<KeyValue> value) {
        this.value = value;
    }

    WhitedConfigType(String key, String keyName, List<WhitedRuleOperatorEnum> operatorList, List<KeyValue> value) {
        this.key = key;
        this.keyName = keyName;
        this.operatorList = operatorList;
        this.value = value;
    }

    public void setOperator(List<WhitedRuleOperatorEnum> operatorList) {
        this.operatorList = operatorList;
    }


    /**
     * 初始化需要延迟加载的Bean
     */
    public static void initData() {
        // 设置云账号初始值
        CloudAccountMapper cloudAccountMapper = SpringUtils.getBean(CloudAccountMapper.class);
        cloudAccountId.setValue(cloudAccountMapper.findList(CloudAccountDTO.builder().build()).stream()
                .map(e -> new WhitedConfigType.KeyValue(e.getCloudAccountId(), e.getCloudAccountId())).toList());

        // 设置规则初始值
//        RuleMapper ruleMapper = SpringUtils.getBean(RuleMapper.class);
//        RuleDTO ruleDTO = RuleDTO.builder().status(Status.valid.name()).build();
//        List<RulePO> rulePOS = ruleMapper.findList(ruleDTO);
//        if (rulePOS != null) {
//            ruleCode.setValue(rulePOS.stream().map(e -> new WhitedConfigType.KeyValue(e.getId(), e.getRuleCode())).toList());
//        }

       //设置资源类型
        ResourceMapper resourceMapper = SpringUtils.getBean(ResourceMapper.class);
        resourceType.setValue(resourceMapper.findAll().stream().map(e -> new WhitedConfigType.KeyValue(e.getResourceType(), e.getResourceType())).collect(Collectors.toSet()).stream().toList());
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

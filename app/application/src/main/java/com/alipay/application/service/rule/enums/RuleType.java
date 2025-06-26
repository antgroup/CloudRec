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
package com.alipay.application.service.rule.enums;


/*
 *@title RuleType
 *@description 规则的类型
 *@author jietian
 *@version 1.0
 *@create 2025/3/17 15:51
 */
public enum RuleType {

    safety_protection("安全防护", "Security Protection"),
    network_access("网络访问", "Network Access"),
    log_audit("日志审计", "Audit Logging"),
    identity_security("身份安全", "Identity Security"),
    data_protection("数据保护", "Data Protection");


    private String ruleType;

    private String ruleTypeEn;

    RuleType(String ruleType, String ruleTypeEn) {
        this.ruleType = ruleType;
        this.ruleTypeEn = ruleTypeEn;
    }


    public String getRuleType() {
        return ruleType;
    }

    public void setRuleType(String ruleType) {
        this.ruleType = ruleType;
    }

    public String getRuleTypeEn() {
        return ruleTypeEn;
    }

    public void setRuleTypeEn(String ruleTypeEn) {
        this.ruleTypeEn = ruleTypeEn;
    }

    public static String getByRuleTypeEn(String ruleType) {
        for (RuleType value : values()) {
            if (value.getRuleType().equals(ruleType)) {
                return value.getRuleTypeEn();
            }
        }
        return "Undefined";
    }
}


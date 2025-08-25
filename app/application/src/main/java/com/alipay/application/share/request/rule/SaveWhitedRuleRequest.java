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
package com.alipay.application.share.request.rule;

import lombok.Data;

import java.util.List;

/**
 * Date: 2025/3/13
 * Author: lz
 */
@Data
public class SaveWhitedRuleRequest {

    /**
     * 规则id
     */
    private Long id;

    /**
     * 规则类型 RULE_ENGINE(规则引擎)，REGO（rego）
     */
    private String ruleType;

    /**
     * 规则名称
     */
    private String ruleName;

    /**
     * 规则描述
     */
    private String ruleDesc;

    /**
     * 风险code
     */
    private String riskRuleCode;

    /**
     * 规则条件json
     */
    private List<WhitedRuleConfigDTO> ruleConfigList;

    /**
     * 条件关系描述
     */
    private String condition;

    /**
     * rego规则内容
     */
    private String regoContent;

    /**
     * 是否启用 0-不启用，1-启用
     */
    private int enable;
}

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
package com.alipay.dao.dto;
/*
 *@title RuleVO
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/5 16:50
 */

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@EqualsAndHashCode(callSuper = true)
@Getter
@Setter
@Builder
public class RuleDTO extends PageDTO {

    private Long id;

    private List<Long> ruleIdList;

    private Long ruleGroupId;

    private List<Long> ruleGroupIdList;

    private String ruleName;

    private String ruleNameEqual;

    private String riskLevel;

    private List<String> riskLevelList;

    private String platform;

    private List<String> platformList;

    private String resourceType;

    private Long ruleRegoId;

    private String ruleDesc;

    private String groupName;

    private List<String> groupNameList;

    private String status;

    private List<Long> ruleTypeIdList;

    private List<String> resourceTypeList;

    /**
     * Used to sort by a specific field
     */
    private String sortParam;

    /**
     * ASC OR DESC
     */
    private String sortType;

    private List<String> ruleCodeList;

    /**
     * tenantId list
     */
    private List<Long> tenantIdList;

    private Long tenantId;
}

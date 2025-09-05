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
package com.alipay.application.share.request.rule;/*
 *@title ListRuleRequest
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/5 16:52
 */

import com.alipay.application.share.request.base.BaseRequest;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class ListRuleRequest extends BaseRequest {

    /**
     * 规则组id
     */
    private List<Long> ruleGroupIdList;

    /**
     * 规则名称list
     */
    private String ruleName;

    /**
     * 风险等级 High,Medium,Low
     */
    private String riskLevel;

    private List<String> riskLevelList;

    /**
     * 平台
     */
    private String platform;

    private List<String> platformList;

    /**
     * 资源类型
     */
    private String resourceType;

    /**
     * 资源类型list
     */
    private List<List<String>> resourceTypeList;

    /**
     * 规则描述
     */
    private String ruleDesc;

    /**
     * 规则组名称
     */
    private String groupName;

    /**
     * 规则组名称list
     */
    private List<String> groupNameList;

    /**
     * 规则类型id 列表
     */
    private List<List<Long>> ruleTypeIdList;

    /**
     * rule status
     */
    private String status;

    /**
     * Used to sort by a specific field
     */
    private String sortParam;

    /**
     * ASC OR DESC
     */
    private String sortType;

    /**
     * rule Code list 规则的不变唯一标识
     */
    private List<String> ruleCodeList;

    /**
     * 默认规则：default
     * 租户自选：selected
     * 全部规则：all
     */
    private String effectRuleType;
}

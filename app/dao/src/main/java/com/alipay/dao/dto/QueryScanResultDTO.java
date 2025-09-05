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


import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.List;

/*
 *@title QueryScanResultRequest
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/1/6 11:24
 */
@Getter
@Setter
public class QueryScanResultDTO extends BaseScrollDTO {

    /**
     * 云账号id
     */
    private String cloudAccountId;

    /**
     * 规则编码
     */
    private String ruleCode;

    /**
     * ruleId
     */
    private Long ruleId;

    /**
     * 租户id
     */
    private Long tenantId;

    /**
     * 创建开始时间
     */
    private Date createStartTime;

    /**
     * 创建结束时间
     */
    private Date createEndTime;

    /**
     * 风险状态
     * REPAIRED, // 已修复
     * UNREPAIRED, // 未修复
     * IGNORED, // 已忽略
     * WHITED, // 已加白
     */
    private String status;

    private List<String> statusList;

    private List<Long> ruleIdList;

    private String platform;

    private String resourceType;

    private String gmtModifiedStart;

    private String gmtModifiedEnd;

}

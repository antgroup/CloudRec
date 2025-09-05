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
package com.alipay.application.share.vo.whited;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.util.Date;

/**
 * Date: 2025/3/20
 * Author: lz
 */

@Data
public class WhitedRuleConfigVO {

    private Long id;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtCreate;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtModified;

    private String ruleType;

    private String ruleName;

    private String ruleDesc;

    private String ruleConfig;

    private String condition;

    private String ruleConfigJson;

    private String regoContent;

    private Long tenantId;

    private String tenantName;

    private String creator;

    private String lockHolder;

    private int enable;

    private String riskRuleCode;

    /**
     * 创建人名称
     */
    private String creatorName;

    /**
     * 锁定人名称
     */
    private String lockHolderName;

    private Boolean isLockHolder;
}

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

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.List;

/*
 *@title CloudAccountDTO
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/20 11:07
 */
@Getter
@Setter
@Builder
public class CloudAccountDTO extends PageDTO {

    private Long id;

    /**
     * 云平台
     */
    private List<String> platformList;

    /**
     * 账号名称
     */
    private String cloudAccountId;

    /**
     * 邮箱
     */
    private String email;

    /**
     * 账号别名
     */
    private String alias;

    /**
     * query by cloudAccountId or cloudAccountName
     */
    private String cloudAccountSearch;

    /**
     * AK、SK 状态
     */
    private String status;

    /**
     * 账号类型
     */
    private String accountStatus;


    /**
     * credentialsJson
     */
    private String credentialsJson;

    /**
     * 平台
     */
    private String platform;

    private String userId;

    /**
     * 资源类型
     */
    private List<String> resourceTypeList;

    private String collectorStatus;

    private Date gmtCreateEnd;

    /**
     * 部署站点
     */
    private String site;

    /**
     * owner
     */
    private String owner;

    /**
     * 租户id
     */
    private Long tenantId;

    /**
     * 代理配置JSON
     */
    private String proxyConfig;
}

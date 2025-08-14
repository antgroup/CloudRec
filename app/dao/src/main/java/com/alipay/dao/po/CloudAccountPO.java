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
package com.alipay.dao.po;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class CloudAccountPO {
    private Long id;

    private Date gmtCreate;

    private Date gmtModified;

    private String cloudAccountId;

    private String alias;

    private String platform;

    // ak, sk status
    private String status;

    private String userId;

    private Long tenantId;

    private Date lastScanTime;

    private String resourceTypeList;

    // Current collection status of the account
    private String collectorStatus;

    // Is the account enabled or disabled
    private String accountStatus;

    private String credentialsJson;

    private String site;

    private String owner;

    private String proxyConfig;

    private String email;

    private Integer enableInverseSelection;
}
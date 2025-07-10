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
package com.alipay.application.share.request.account;

/*
 *@title SaveCloudAccountRequest
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/20 11:25
 */

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;

@Data
public class SaveCloudAccountRequest {

    /**
     * 主键
     */
    private Long id;

    /**
     * 云账号id
     */
    @NotEmpty(message = "云账号id不能为空")
    private String cloudAccountId;

    /**
     * 邮箱
     */
    private String email;

    /**
     * 云账号别名
     */
    private String alias;

    /**
     * 认证信息
     */
    private Object credentialsObj;

    /**
     * 平台标识
     */
    @NotEmpty(message = "平台标识不能为空")
    private String platform;

    /**
     * 部署站点
     */
    private String site;

    /**
     * 对接的云服务，从获取资产类型接口获取
     */
    private List<List<String>> resourceTypeList;

    /**
     * 租户id
     */
    @NotNull(message = "租户id不能为空")
    private Long tenantId;

    /**
     * 云账号的负责人
     */
    private String owner;

    /**
     * 代理配置JSON
     */
    private String proxyConfig;
}

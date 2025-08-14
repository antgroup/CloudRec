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
package com.alipay.application.share.vo.collector;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

/*
 *@title Registry
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/21 13:58
 */
@Getter
@Setter
public class Registry {

    /**
     * 平台信息
     */
    private String platform;

    /**
     * 执行地址信息
     */
    private String registryValue;

    /**
     * collector 执行的云账号id列表
     */
    private List<String> cloudAccountIdList;

    /**
     * cron表达式
     */
    private String cron;

    /**
     * agent名称
     */
    private String agentName;

    /**
     * 对称加密的KEY
     */
    private String secretKey;

    /**
     * 一次性注册token
     */
    private String onceToken;

    /**
     * 站点
     */
    private List<String> sites;

    /**
     * 健康状态
     */
    private HealthStatus healthStatus;

    @Getter
    @Setter
    public static class RegistryResponse {

        /**
         * 持久化token
         */
        private String persistentToken;

        /**
         * collector 状态
         */
        private String status;
    }


    @Getter
    @Setter
    public static class HealthStatus {
        private String cpuUsage;
        private String memoryUsage;
        private String diskUsage;
    }
}

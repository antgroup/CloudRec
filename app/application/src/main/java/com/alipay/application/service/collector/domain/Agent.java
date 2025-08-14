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
package com.alipay.application.service.collector.domain;


import com.alipay.common.enums.Status;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.UUID;

/*
 *@title Agent
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/1/17 17:36
 */
@Getter
@Setter
public class Agent {

    private Long id;

    private Date gmtCreate;

    private Date gmtModified;

    private String platform;

    private String registryValue;

    private Date registryTime;

    private String cron;

    private String status;

    private String agentName;

    private String cloudAccountId;

    private String secretKey;

    private String persistentToken;

    private String onceToken;

    private String healthStatus;

    public static Agent newAgent(String platform, String registryValue, String cron, String agentName, String secretKey,
                                 String onceToken, String healthStatus) {
        Agent agent = new Agent();
        agent.setPlatform(platform);
        agent.setRegistryValue(registryValue);
        agent.setRegistryTime(new Date());
        agent.setStatus(Status.valid.name());
        agent.setAgentName(agentName);
        agent.setCron(cron);
        agent.setSecretKey(secretKey);
        agent.setPersistentToken(UUID.randomUUID().toString());
        agent.setOnceToken(onceToken);
        agent.setHealthStatus(healthStatus);
        return agent;
    }

    public void refreshAgent(String token, String secretKey, String healthStatus) {
        this.setRegistryTime(new Date());
        this.setStatus(Status.valid.name());
        this.setCron(cron);
        this.setAgentName(agentName);
        this.setSecretKey(secretKey);
        this.setOnceToken(token);
        this.setHealthStatus(healthStatus);
    }
}

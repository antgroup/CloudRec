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

import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.dao.mapper.AgentRegistryTokenMapper;
import com.alipay.dao.mapper.UserMapper;
import com.alipay.dao.po.AgentRegistryPO;
import com.alipay.dao.po.AgentRegistryTokenPO;
import com.alipay.dao.po.UserPO;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import org.springframework.beans.BeanUtils;

import java.util.Date;

@Data
public class AgentRegistryVO {

    /**
     * id
     */
    private Long id;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtCreate;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtModified;

    /**
     * 平台
     */
    private String platform;

    /**
     * 注册地址
     */
    private String registryValue;

    /**
     * 注册时间
     */
    private Date registryTime;

    /**
     * 注册cron
     */
    private String cron;

    /**
     * 状态
     */
    private String status;

    /**
     * collector 名称
     */
    private String agentName;

    /**
     * 加密密钥
     */
    private String secretKey;

    /**
     * 持久化token
     */
    private String persistentToken;

    /**
     * 部署token
     */
    private String onceToken;

    /**
     * 部署人
     */
    private String username;

    /**
     * 健康状态：CPU、内存、磁盘
     *
     */
    private String healthStatus;

    public static AgentRegistryVO build(AgentRegistryPO agentRegistryPO) {
        if (agentRegistryPO == null) {
            return null;
        }

        AgentRegistryVO agentRegistryVO = new AgentRegistryVO();
        BeanUtils.copyProperties(agentRegistryPO, agentRegistryVO);

        AgentRegistryTokenMapper agentRegistryTokenMapper = SpringUtils.getApplicationContext()
                .getBean(AgentRegistryTokenMapper.class);
        AgentRegistryTokenPO agentRegistryTokenPO = agentRegistryTokenMapper
                .findOne(agentRegistryPO.getOnceToken());
        if (agentRegistryTokenPO != null) {
            UserMapper userMapper = SpringUtils.getApplicationContext().getBean(UserMapper.class);
            UserPO userPO = userMapper.findOne(agentRegistryTokenPO.getUserId());
            if (userPO != null) {
                agentRegistryVO.setUsername(userPO.getUsername());
            }
        }

        return agentRegistryVO;
    }
}
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

import com.alibaba.fastjson.JSON;
import com.alipay.application.service.account.utils.AESEncryptionUtils;
import com.alipay.application.service.account.utils.PlatformUtils;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.dao.mapper.CollectorRecordMapper;
import com.alipay.dao.po.AgentRegistryPO;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.CollectorRecordPO;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Data
public class AgentCloudAccountVO {

    private static final Logger LOGGER = LoggerFactory.getLogger(AgentCloudAccountVO.class);

    /**
     * 云账号id
     */
    private String cloudAccountId;

    /**
     * 平台标识
     */
    private String platform;

    /**
     * 资源类型
     */
    private List<String> resourceTypeList;

    /**
     * 认证信息
     */
    private String credentialJson;

    /**
     * 采集ID，用于日志上报
     */
    private Long collectRecordId;

    /**
     * 采集任务参数
     */
    private CollectorTask collectorTask;


    @Getter
    @Setter
    public static class CollectorTask {
        private Long taskId;
        private String taskType;
        private String paramJson;
    }


    // build collector account account vo
    public static AgentCloudAccountVO build(CloudAccountPO cloudAccountPO, AgentRegistryPO agentRegistryPO) throws Exception {
        if (cloudAccountPO == null) {
            return null;
        }

        // platform info
        AgentCloudAccountVO agentCloudAccountVO = new AgentCloudAccountVO();
        agentCloudAccountVO.setCloudAccountId(cloudAccountPO.getCloudAccountId());
        agentCloudAccountVO.setPlatform(cloudAccountPO.getPlatform());

        Map<String, String> accountCredentialsInfo = PlatformUtils.getAccountCredentialsInfo(cloudAccountPO.getPlatform(), PlatformUtils.decryptCredentialsJson(cloudAccountPO.getCredentialsJson()));
        agentCloudAccountVO.setCredentialJson(AESEncryptionUtils.encrypt(JSON.toJSONString(accountCredentialsInfo), agentRegistryPO.getSecretKey()));

        if (StringUtils.isNoneEmpty(cloudAccountPO.getResourceTypeList())) {
            agentCloudAccountVO.setResourceTypeList(Arrays.asList(cloudAccountPO.getResourceTypeList().split(",")));
        }

        // init collector record
        CollectorRecordMapper collectorRecordMapper = SpringUtils.getBean(CollectorRecordMapper.class);
        CollectorRecordPO collectorRecordPO = new CollectorRecordPO();
        collectorRecordPO.setCloudAccountId(cloudAccountPO.getCloudAccountId());
        collectorRecordPO.setPlatform(cloudAccountPO.getPlatform());
        collectorRecordPO.setStartTime(new Date());
        collectorRecordPO.setRegistryValue(agentRegistryPO.getRegistryValue());
        collectorRecordMapper.insertSelective(collectorRecordPO);

        agentCloudAccountVO.setCollectRecordId(collectorRecordPO.getId());

        return agentCloudAccountVO;
    }
}
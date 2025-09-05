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
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alipay.application.service.account.utils.AESEncryptionUtils;
import com.alipay.application.service.account.utils.PlatformUtils;
import com.alipay.application.service.collector.domain.CollectRecordInfo;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.dao.mapper.CollectorRecordMapper;
import com.alipay.dao.po.AgentRegistryPO;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.CollectorRecordPO;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Data
public class AgentCloudAccountVO {

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
     * 采集记录信息
     */
    private CollectRecordInfo collectRecordInfo;

    /**
     * 采集任务参数
     */
    private CollectorTask collectorTask;

    /**
     * 代理配置
     */
    private String proxyConfig;


    @Getter
    @Setter
    public static class CollectorTask {
        private Long taskId;
        private String taskType;
        private String paramJson;
    }

    private static final CollectorRecordMapper collectorRecordMapper = SpringUtils.getBean(CollectorRecordMapper.class);

    private static CollectRecordInfo initCollectRecordInfo(CloudAccountPO cloudAccountPO, AgentRegistryPO agentRegistryPO) {
        CollectorRecordPO collectorRecordPO = new CollectorRecordPO();
        collectorRecordPO.setStartTime(new Date());
        collectorRecordPO.setRegistryValue(agentRegistryPO.getRegistryValue());
        collectorRecordPO.setPlatform(cloudAccountPO.getPlatform());
        collectorRecordPO.setCloudAccountId(cloudAccountPO.getCloudAccountId());
        CollectRecordInfo collectRecordInfo = new CollectRecordInfo();
        collectRecordInfo.setPlatform(cloudAccountPO.getPlatform());
        collectRecordInfo.setCloudAccountId(cloudAccountPO.getCloudAccountId());
        collectorRecordPO.setCollectRecordInfo(JSON.toJSONString(collectRecordInfo, SerializerFeature.WriteMapNullValue));
        collectorRecordMapper.insertSelective(collectorRecordPO);

        // set collect record id
        collectRecordInfo.setCollectRecordId(collectorRecordPO.getId());
        return collectRecordInfo;
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
        agentCloudAccountVO.setProxyConfig(cloudAccountPO.getProxyConfig());

        Map<String, String> accountCredentialsInfo = PlatformUtils.getAccountCredentialsInfo(cloudAccountPO.getPlatform(), PlatformUtils.decryptCredentialsJson(cloudAccountPO.getCredentialsJson()));
        agentCloudAccountVO.setCredentialJson(AESEncryptionUtils.encrypt(JSON.toJSONString(accountCredentialsInfo), agentRegistryPO.getSecretKey()));

        if (StringUtils.isNoneEmpty(cloudAccountPO.getResourceTypeList())) {
            agentCloudAccountVO.setResourceTypeList(Arrays.asList(cloudAccountPO.getResourceTypeList().split(",")));
        }

        if (cloudAccountPO.getEnableInverseSelection() == 1) {
            List<String> allResourceType = new ArrayList<>(PlatformUtils.getResourceType(cloudAccountPO.getPlatform()));
            allResourceType.removeAll(agentCloudAccountVO.getResourceTypeList());
            agentCloudAccountVO.setResourceTypeList(allResourceType);
        }

        // set last collect record info
        CollectorRecordPO lastOneRecord = collectorRecordMapper.findLastOne(cloudAccountPO.getCloudAccountId());
        // Do not modify the location of the record initialization code
        CollectRecordInfo currentRecord = initCollectRecordInfo(cloudAccountPO, agentRegistryPO);
        agentCloudAccountVO.setCollectRecordId(currentRecord.getCollectRecordId());

        if (lastOneRecord != null && StringUtils.isNoneEmpty(lastOneRecord.getCollectRecordInfo())) {
            // use last one collect record info
            CollectRecordInfo info = JSON.parseObject(lastOneRecord.getCollectRecordInfo(), CollectRecordInfo.class);
            info.setCollectRecordId(currentRecord.getCollectRecordId());
            agentCloudAccountVO.setCollectRecordInfo(info);
        } else {
            // use current collect record info
            agentCloudAccountVO.setCollectRecordInfo(currentRecord);
        }

        return agentCloudAccountVO;
    }
}
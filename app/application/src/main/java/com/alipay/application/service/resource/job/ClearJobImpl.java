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
package com.alipay.application.service.resource.job;


import com.alipay.application.service.common.utils.DbCacheUtil;
import com.alipay.application.service.resource.DelResourceService;
import com.alipay.application.service.risk.RiskStatusManager;
import com.alipay.application.service.risk.domain.repo.RiskRepository;
import com.alipay.common.enums.ResourceStatus;
import com.alipay.common.enums.Status;
import com.alipay.dao.mapper.CloudAccountMapper;
import com.alipay.dao.mapper.CloudResourceInstanceMapper;
import com.alipay.dao.mapper.RuleScanResultMapper;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.CloudResourceInstancePO;
import com.google.common.collect.Lists;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

/*
 *@title ClearJobImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/12/31 10:35
 */

@Slf4j
@Component
public class ClearJobImpl implements ClearJob {

    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private CloudAccountMapper cloudAccountMapper;

    @Resource
    private DbCacheUtil dbCacheUtil;

    @Resource
    private RiskStatusManager riskStatusManager;

    @Resource
    private DelResourceService delResourceService;

    @Resource
    private RiskRepository riskRepository;

    /**
     * The number of assets deleted at a time
     */
    private static final int MAX_DEL_NUM = 2;

    @Override
    public void clearObsoleteData() {
        log.info("clear obsolete data start");
        List<CloudAccountPO> list = cloudAccountMapper.findAll();
        for (CloudAccountPO po : list) {
            clearExpiredDataByCloudAccount(po.getCloudAccountId());
        }
        log.info("clear obsolete data end");
    }


    private void clearExpiredDataByCloudAccount(String cloudAccountId) {
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(cloudAccountId);
        if (cloudAccountPO == null) {
            return;
        }
        if (Objects.equals(Status.running.name(), cloudAccountPO.getCollectorStatus())) {
            return;
        }

        // Delete the data of the disabled account
        if (Objects.equals(Status.invalid.name(), cloudAccountPO.getAccountStatus())) {
            delResourceService.removeResource(cloudAccountPO.getCloudAccountId());
            riskRepository.remove(cloudAccountPO.getCloudAccountId());
        }

        try {
            List<Long> idList = cloudResourceInstanceMapper.findPreDeletedDataIdList(cloudAccountId, MAX_DEL_NUM);
            if (!idList.isEmpty()) {
                // idList too large, split and delete
                List<List<Long>> idListSplit = Lists.partition(idList, 100);
                for (List<Long> idListSub : idListSplit) {
                    Thread.sleep(200);
                    // 1. change risk status
                    ruleScanResultMapper.updateResourceStatus(idListSub, ResourceStatus.not_exist.name());
                    for (Long id : idListSub) {
                        CloudResourceInstancePO cloudResourceInstancePO = cloudResourceInstanceMapper.selectByPrimaryKey(id);
                        if (cloudResourceInstancePO != null) {
                            riskStatusManager.unrepairedToRepaired(cloudResourceInstancePO.getResourceId(), cloudResourceInstancePO.getResourceType(), cloudResourceInstancePO.getPlatform());
                        }
                    }
                    // 2. delete resource
                    cloudResourceInstanceMapper.deletedByIdList(idListSub);
                }
            }
        } catch (Exception e) {
            log.error("clear obsolete data error", e);
        }
    }

    @Override
    public void commitDeleteResourceByCloudAccount(String cloudAccountId) {
        List<Long> idList = cloudResourceInstanceMapper.findPreDeletedDataIdList(cloudAccountId, MAX_DEL_NUM);
        if (!idList.isEmpty()) {
            log.info("Pre deleted data found for cloud account: {}: idList size: {}", cloudAccountId, idList.size());
            // idList too large, split and delete
            List<List<Long>> idListSplit = Lists.partition(idList, 300);
            for (List<Long> idListSub : idListSplit) {
                // 1. change risk status
                ruleScanResultMapper.updateResourceStatus(idListSub, ResourceStatus.not_exist.name());
                for (Long id : idListSub) {
                    CloudResourceInstancePO cloudResourceInstancePO = cloudResourceInstanceMapper.selectByPrimaryKey(id);
                    if (cloudResourceInstancePO != null) {
                        riskStatusManager.unrepairedToRepaired(cloudResourceInstancePO.getResourceId(), cloudResourceInstancePO.getResourceType(), cloudResourceInstancePO.getPlatform());
                    }
                }
            }

            // If the deletion mark is not cleared after two pre-deletions, it will be physically deleted directly.
            cloudResourceInstanceMapper.commitDeleteByCloudAccountId(cloudAccountId, MAX_DEL_NUM);
        }
    }

    @Override
    public void cacheClearHandler() {
        dbCacheUtil.clear();
    }
}



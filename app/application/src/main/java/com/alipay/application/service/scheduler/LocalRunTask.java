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
package com.alipay.application.service.scheduler;

import com.alipay.application.config.annotate.ConditionalOnLocalScheduler;
import com.alipay.application.service.collector.AgentService;
import com.alipay.application.service.resource.job.ClearJob;
import com.alipay.application.service.risk.job.SubscriptionJobService;
import com.alipay.application.service.rule.job.ScanService;
import com.alipay.application.service.statistics.job.StatisticsJob;
import com.alipay.application.service.statistics.job.SyncDataJob;
import lombok.Synchronized;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Date: 2025/3/4
 * Author: lz
 */
@Component
@ConditionalOnLocalScheduler
@EnableScheduling
public class LocalRunTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(LocalRunTask.class);

    @Autowired
    private StatisticsJob statisticsJob;

    @Autowired
    private ClearJob clearJob;

    @Autowired
    private SyncDataJob syncDataJob;

    @Autowired
    private AgentService agentService;

    @Autowired
    private SubscriptionJobService subscriptionJobService;

    @Autowired
    private LocalTaskLocksService localTaskLocksService;

    @Autowired
    private ScanService scanService;


    /**
     * 健康检查 每60秒执行一次
     */
    @Synchronized
    @Scheduled(fixedRate = 60000)
    public void healthCheck_local() {
        boolean runStatus = Boolean.TRUE;
        String msg = null;
        try {
            LOGGER.info("healthCheck_local start");
            localTaskLocksService.lockTask("healthCheck");
            agentService.HealthCheck();
        } catch (Exception e) {
            runStatus = Boolean.FALSE;
            msg = e.getMessage();
            LOGGER.error("healthCheck_local error", e);
            throw new RuntimeException(e);
        } finally {
            //释放锁
            localTaskLocksService.releaseLockTask("healthCheck", runStatus, msg);
        }
    }


    /**
     * 定时告警任务
     */
    @Synchronized
    @Scheduled(cron = "0 0 0/1 * * ?")
    public void timeNotifyHandler_local() {
        boolean runStatus = Boolean.TRUE;
        String msg = null;
        try {
            LOGGER.info("timeNotifyHandler_local start");
            localTaskLocksService.lockTask("timeNotifyHandler");
            subscriptionJobService.timeNotifyHandler();
        } catch (Exception e) {
            LOGGER.error("timeNotifyHandler_local error", e);
            runStatus = Boolean.FALSE;
            msg = e.getMessage();
            throw new RuntimeException(e);
        } finally {
            //释放锁
            localTaskLocksService.releaseLockTask("timeNotifyHandler", runStatus, msg);
        }
    }

    /**
     * 初始化采集状态
     */
    @Synchronized
    @Scheduled(cron = "0 0 1 * * ?")
    public void initCloudAccountCollectStatus_local() {
        boolean runStatus = Boolean.TRUE;
        String msg = null;
        try {
            LOGGER.info("initCloudAccountCollectStatus_local start");
            localTaskLocksService.lockTask("initCloudAccountCollectStatus");
            agentService.initCloudAccountCollectStatus();
        } catch (Exception e) {
            LOGGER.error("initCloudAccountCollectStatus_local error", e);
            runStatus = Boolean.FALSE;
            msg = e.getMessage();
            throw new RuntimeException(e);
        } finally {
            //释放锁
            localTaskLocksService.releaseLockTask("initCloudAccountCollectStatus", runStatus, msg);
        }

    }


    /**
     * 统计全部数据
     */
    @Synchronized
    @Scheduled(cron = "0 0 1 * * ?")
    public void resourceRiskCountStatisticsHandler_local() {
        boolean runStatus = Boolean.TRUE;
        String msg = null;
        try {
            LOGGER.info("statisticsAllHandler_local start");
            localTaskLocksService.lockTask("statisticsAllHandler");
            statisticsJob.statisticsAll();
        } catch (Exception e) {
            LOGGER.error("statisticsAllHandler_local error", e);
            runStatus = Boolean.FALSE;
            msg = e.getMessage();
            throw new RuntimeException(e);
        } finally {
            //释放锁
            localTaskLocksService.releaseLockTask("statisticsAllHandler", runStatus, msg);
        }
    }

    /**
     * 定期清理过期的数据
     */
    @Synchronized
    @Scheduled(cron = "0 0 23 * * ?")
    public void clearObsoleteDataHandler_local() {
        boolean runStatus = Boolean.TRUE;
        String msg = null;
        try {
            LOGGER.info("clearObsoleteData_local start");
            localTaskLocksService.lockTask("clearObsoleteData");
            clearJob.clearObsoleteData();
        } catch (Exception e) {
            LOGGER.error("clearObsoleteData_local error", e);
            runStatus = Boolean.FALSE;
            msg = e.getMessage();
            throw new RuntimeException(e);
        } finally {
            //释放锁
            localTaskLocksService.releaseLockTask("clearObsoleteData", runStatus, msg);
        }
    }


    /**
     * 定时同步云产品身份相关数据
     */
    @Synchronized
    @Scheduled(cron = "0 0 1 * * ?")
    public void syncCloudDataHandler_local() {
        boolean runStatus = Boolean.TRUE;
        String msg = null;
        try {
            LOGGER.info("syncCloudDataHandler start");
            localTaskLocksService.lockTask("syncCloudDataHandler");
            syncDataJob.syncCloudDataHandler();
        } catch (Exception e) {
            LOGGER.error("syncCloudDataHandler_local error", e);
            runStatus = Boolean.FALSE;
            msg = e.getMessage();
            throw new RuntimeException(e);
        } finally {
            //释放锁
            localTaskLocksService.releaseLockTask("syncCloudDataHandler", runStatus, msg);
        }
    }

    /**
     * 定时扫描规则
     */
    @Synchronized
    @Scheduled(cron = "0 0 0/4 * * ?")
    public void syncScanAll_local() {
        boolean runStatus = Boolean.TRUE;
        String msg = null;
        try {
            LOGGER.info("syncScanAll_local start");
            localTaskLocksService.lockTask("scanAllHandler");
            clearJob.clearObsoleteData();
            scanService.scanAll();
        } catch (Exception e) {
            LOGGER.error("syncScanAll_local error", e);
            runStatus = Boolean.FALSE;
            msg = e.getMessage();
            throw new RuntimeException(e);
        } finally {
            //释放锁
            localTaskLocksService.releaseLockTask("scanAllHandler", runStatus, msg);
        }
    }


}

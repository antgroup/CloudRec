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

import com.alipay.dao.mapper.LocalTaskExecuteLogMapper;
import com.alipay.dao.mapper.LocalTaskLocksMapper;
import com.alipay.dao.po.LocalTaskExecuteLogPO;
import com.alipay.dao.po.LocalTaskLocksPO;
import jakarta.annotation.Resource;
import lombok.Synchronized;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

/**
 * Date: 2025/3/4
 * Author: lz
 */
@Slf4j
@Service
public class LocalTaskLocksServiceImpl implements LocalTaskLocksService {

    @Resource
    private LocalTaskLocksMapper localTaskLocksMapper;

    @Resource
    private LocalTaskExecuteLogMapper localTaskExecuteLogMapper;

    @Override
    public LocalTaskLocksPO getByTaskName(String taskName) {
        return localTaskLocksMapper.selectByTaskName(taskName);
    }

    @Synchronized
    @Override
    public Boolean lockTask(String taskName) {
        try {
            InetAddress inetAddress = InetAddress.getLocalHost();
            String hostAddress = inetAddress.getHostAddress();
            log.info("query task status,  taskName:{}, hostAddress:{}", taskName, hostAddress);
            LocalTaskLocksPO localTaskLocksPO = localTaskLocksMapper.selectByTaskName(taskName);
            if (Objects.nonNull(localTaskLocksPO)) {
                //当前任务正在运行,判断锁过期
                LocalTaskExecuteLogPO localTaskExecuteLogPO = localTaskExecuteLogMapper.selectByTaskName(taskName);
                if (Objects.nonNull(localTaskExecuteLogPO) && Objects.isNull(localTaskExecuteLogPO.getEndTime())) {
                    localTaskLocksPO.getGmtCreate();
                    boolean moreThanOneMinute = isMoreThanOneMinute(localTaskLocksPO.getGmtCreate());
                    if (moreThanOneMinute) {
                        releaseLockTask(taskName, false, "lock timeout");
                        log.info("lock timeout and task not finish , release lock, taskName:{}, hostAddress:{}", taskName, hostAddress);
                        return true;
                    }
                }

                return false;
            }

            // 插入锁记录
            localTaskLocksPO = new LocalTaskLocksPO();
            localTaskLocksPO.setTaskName(taskName);
            localTaskLocksPO.setExecuteHost(hostAddress);
            int insert = localTaskLocksMapper.insertSelective(localTaskLocksPO);

            //插入定时任务执行记录
            LocalTaskExecuteLogPO localTaskExecuteLogPO = new LocalTaskExecuteLogPO();
            localTaskExecuteLogPO.setExecuteHost(hostAddress);
            localTaskExecuteLogPO.setTaskName(taskName);
            localTaskExecuteLogPO.setStartTime(new Date());
            localTaskExecuteLogMapper.insertSelective(localTaskExecuteLogPO);

            if (insert == 0) {
                log.info("LocalTaskLocks insert lock record failed");
                return false;
            }
            return true;
        } catch (UnknownHostException e) {
            log.error("query freeStatus error", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void releaseLockTask(String taskName, Boolean runStatus, String errorMsg) {
        try {
            InetAddress inetAddress = InetAddress.getLocalHost();
            //更新定时任务执行记录
            LocalTaskExecuteLogPO localTaskExecuteLogPO = localTaskExecuteLogMapper.selectByTaskName(taskName);
            if(Objects.nonNull(localTaskExecuteLogPO) && Objects.isNull(localTaskExecuteLogPO.getEndTime())){
                localTaskExecuteLogPO.setGmtModified(new Date());
                localTaskExecuteLogPO.setEndTime(new Date());
                localTaskExecuteLogPO.setResult(runStatus ? "success" : "fail");
                localTaskExecuteLogPO.setMsg(errorMsg);
                localTaskExecuteLogMapper.updateByPrimaryKeySelective(localTaskExecuteLogPO);
            }
            //释放锁
            log.info("release lock task, hostAddress:{}, taskName:{}", inetAddress.getHostAddress(), taskName);
            localTaskLocksMapper.deleteByTaskName(taskName);
        } catch (UnknownHostException e) {
            log.error("release lock task error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * 是否大于1分钟
     *
     * @param gmtCreate
     * @return
     */
    public boolean isMoreThanOneMinute(Date gmtCreate) {
        Instant now = Instant.now();
        Instant gmtCreateInstant = gmtCreate.toInstant();
        Duration duration = Duration.between(gmtCreateInstant, now);

        // 判断时间差是否大于1分钟
        return duration.toMinutes() >= 1;
    }


}

package com.alipay.application.service.collector.domain.repo;


import com.alipay.application.service.collector.domain.TaskResp;
import com.alipay.application.service.collector.enums.TaskStatus;
import com.alipay.application.service.common.utils.DBDistributedLockUtil;
import com.alipay.common.exception.BizException;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.mapper.CloudAccountMapper;
import com.alipay.dao.mapper.CollectorTaskMapper;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.CollectorTaskPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/*
 *@title CollectorTaskRepositoryImpl
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/16 14:14
 */
@Slf4j
@Repository
public class CollectorTaskRepositoryImpl implements CollectorTaskRepository {

    @Resource
    private CollectorTaskMapper collectorTaskMapper;
    @Resource
    private CloudAccountMapper cloudAccountMapper;
    @Resource
    private DBDistributedLockUtil dbDistributedLockUtil;

    private static final String localLockPrefix = "collector_task_";

    @Override
    public void initTask(String cloudAccountId, String taskType) {
        // 1 min distributed lock to prevent multiple clicks during a period of time
        String lockKey = localLockPrefix + cloudAccountId + "_" + taskType;
        if (!dbDistributedLockUtil.tryLock(lockKey, 1000 * 60)) {
            throw new BizException("The task is being created, please wait");
        }

        try {
            CollectorTaskPO collectorTaskPO = new CollectorTaskPO();
            collectorTaskPO.setCloudAccountId(cloudAccountId);
            CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(cloudAccountId);
            if (cloudAccountPO == null) {
                throw new BizException("The cloud account does not exist");
            }

            List<CollectorTaskPO> taskList = collectorTaskMapper.findListByCloudAccount(cloudAccountId, taskType, TaskStatus.getNotEndedStatusList());
            if (CollectionUtils.isNotEmpty(taskList)) {
                throw new BizException("The task already exists");
            }

            collectorTaskPO.setPlatform(cloudAccountPO.getPlatform());
            collectorTaskPO.setType(taskType);
            collectorTaskPO.setUserId(UserInfoContext.getCurrentUser().getUserId());
            collectorTaskPO.setStatus(TaskStatus.waiting.name());
            collectorTaskMapper.insertSelective(collectorTaskPO);
        }catch (Exception e){
            log.error("Duplicate task detected for cloudAccountId: {}, taskType: {}", cloudAccountId, taskType, e);
            throw new BizException(e.getMessage());
        } finally {
            try {
                dbDistributedLockUtil.releaseLock(lockKey);
            } catch (Exception e) {
                log.error("Failed to release distributed lock for key: {}", lockKey, e);
            }
        }
    }


    @Override
    public List<TaskResp> lockTask(String regValue, String platform) {
        List<CollectorTaskPO> list = findExecutableTaskByType(platform);

        // 按 taskType 分组
        Map<String, List<CollectorTaskPO>> taskMap = list.stream().collect(Collectors.groupingBy(CollectorTaskPO::getType));
        List<TaskResp> result = new ArrayList<>();
        for (Map.Entry<String, List<CollectorTaskPO>> entry : taskMap.entrySet()) {
            TaskResp taskResp = new TaskResp();
            taskResp.setTaskType(entry.getKey());

            List<TaskResp.TaskParam> taskParams = new ArrayList<>();
            for (CollectorTaskPO collectorTaskPO : entry.getValue()) {
                TaskResp.TaskParam taskParam = new TaskResp.TaskParam();
                taskParam.setTaskId(collectorTaskPO.getId());
                taskParam.setCloudAccountId(collectorTaskPO.getCloudAccountId());
                taskParams.add(taskParam);

                collectorTaskPO.setRegistryValue(regValue);
                collectorTaskMapper.updateByPrimaryKeySelective(collectorTaskPO);
                collectorTaskPO.setStatus(TaskStatus.locked.name());
                collectorTaskPO.setLockTime(new Date());
                collectorTaskMapper.updateByPrimaryKeySelective(collectorTaskPO);
            }

            taskResp.setTaskParams(taskParams);
            result.add(taskResp);
        }

        return result;
    }


    @Override
    public void updateTaskStatus(List<Long> idList, String status) {
        collectorTaskMapper.updateStatus(idList, status);
    }

    private List<CollectorTaskPO> findExecutableTaskByType(String platform) {
        List<CollectorTaskPO> list = collectorTaskMapper.findList(platform, TaskStatus.getNotEndedStatusList(), 50);

        List<CollectorTaskPO> result = new ArrayList<>();
        for (CollectorTaskPO collectorTaskPO : list) {
            if (TaskStatus.waiting.name().equals(collectorTaskPO.getStatus())) {
                result.add(collectorTaskPO);
            }
            if (TaskStatus.locked.name().equals(collectorTaskPO.getStatus())) {
                // 超过60S collector没有发送信号将任务变更为运行中
                if (System.currentTimeMillis() - collectorTaskPO.getLockTime().getTime() > 60 * 1000) {
                    result.add(collectorTaskPO);
                }
            }
            if (TaskStatus.running.name().equals(collectorTaskPO.getStatus())) {
                // 超过120min，collector没有发送信号将任务变更为已完成
                if (System.currentTimeMillis() - collectorTaskPO.getLockTime().getTime() > 120 * 60 * 1000) {
                    result.add(collectorTaskPO);
                }
            }
        }

        return result;
    }
}

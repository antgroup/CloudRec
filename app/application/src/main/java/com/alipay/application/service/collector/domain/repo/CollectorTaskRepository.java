package com.alipay.application.service.collector.domain.repo;


import com.alipay.application.service.collector.domain.TaskResp;

import java.util.List;

/*
 *@title CollectorTaskRepository
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/16 14:14
 */
public interface CollectorTaskRepository {

    /**
     * 初始化一条任务
     *
     * @param cloudAccountId 云账号ID
     * @param taskType       任务类型
     */
    void initTask(String cloudAccountId, String taskType);

    /**
     * 查找任务类型，并锁定对应的任务，将任务变更为"locked"状态，最多锁定50条任务
     *
     * @param regValue collector 注册的唯一ID
     *                 platform 平台
     * @return 任务类型列表 任务类型:任务ID
     */
    List<TaskResp> lockTask(String regValue, String platform);

    /**
     * 更新任务状态
     *
     * @param idList 任务ID list
     * @param status 任务状态
     */
    void updateTaskStatus(List<Long> idList, String status);

}

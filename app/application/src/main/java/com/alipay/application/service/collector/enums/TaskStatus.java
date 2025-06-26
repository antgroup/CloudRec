package com.alipay.application.service.collector.enums;


import java.util.List;

/*
 *@title TaskStatus
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/16 14:34
 */
public enum TaskStatus {

    waiting, locked, running, done;


    public static List<String> getNotEndedStatusList() {
        return List.of(TaskStatus.waiting.name(), TaskStatus.locked.name(), TaskStatus.running.name());
    }
}

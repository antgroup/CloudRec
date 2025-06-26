package com.alipay.application.service.collector.domain;


import lombok.Getter;
import lombok.Setter;

import java.util.List;

/*
 *@title TaskResp
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/16 14:27
 */
@Getter
@Setter
public class TaskResp {

    private String taskType;

    private List<TaskParam> taskParams;

    @Getter
    @Setter
    public static class TaskParam {
        private Long taskId;
        private String cloudAccountId;
    }
}

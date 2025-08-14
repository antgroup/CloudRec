package com.alipay.application.service.collector.domain;


import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

/*
 *@title CollectorRecordInfo
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/29 10:39
 */
@Getter
@Setter
public class CollectRecordInfo {

    private Long collectRecordId;
    private Boolean enableCollection;
    private String platform;
    private String cloudAccountId;
    private String startTime;
    private String endTime;
    private String errorMessage;
    private String message;
    private List<Map<String, Object>> events;
}

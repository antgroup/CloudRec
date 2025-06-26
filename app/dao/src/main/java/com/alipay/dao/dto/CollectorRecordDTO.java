package com.alipay.dao.dto;


import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
public class CollectorRecordDTO extends PageDTO {

    private Long id;

    private String platform;

    private String cloudAccountId;

    private List<String> startTimeArray;

    private String errorCode;
}
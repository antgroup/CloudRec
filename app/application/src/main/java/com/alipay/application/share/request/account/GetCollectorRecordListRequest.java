package com.alipay.application.share.request.account;


import com.alipay.application.share.request.base.BaseRequest;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

/*
 *@title GetCollectorRecordListRequest
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/13 10:04
 */
@Getter
@Setter
public class GetCollectorRecordListRequest extends BaseRequest {

    private Long id;

    private String cloudAccountId;

    @NotEmpty(message = "platform not empty")
    private String platform;

    private List<String> startTimeArray;

    private String errorCode;
}

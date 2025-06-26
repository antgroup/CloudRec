package com.alipay.application.share.request.account;


import lombok.Getter;
import lombok.Setter;

/*
 *@title CreateCollectTaskRequest
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/13 21:36
 */
@Getter
@Setter
public class CreateCollectTaskRequest {

    private String platform;

    private String cloudAccountId;
}

package com.alipay.application.share.request.rule;


import lombok.Getter;
import lombok.Setter;

/*
 *@title LoadRuleFromGithubRequest
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/23 22:56
 */
@Getter
@Setter
public class LoadRuleFromGithubRequest {

    /**
     * 是否覆盖已存在的规则
     */
    private Boolean coverage;
}

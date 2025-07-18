package com.alipay.application.share.request.rule;


import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

/*
 *@title AddTenantSelectRuleRequest
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/10 13:52
 */
@Getter
@Setter
public class AddTenantSelectRuleRequest {

    @NotEmpty(message = "The rule code cannot be empty")
    private String ruleCode;


    @Override
    public String toString() {
        return "AddTenantSelectRuleRequest{" +
                "ruleCode='" + ruleCode + '\'' +
                '}';
    }
}

package com.alipay.application.share.request.rule;


import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

/*
 *@title BatchDeleteTenantSelectRuleRequest
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/10 16:03
 */
@Getter
@Setter
public class BatchDeleteTenantSelectRuleRequest {

    @NotEmpty(message = "Rule code list cannot be empty")
    private List<String> ruleCodeList;
}

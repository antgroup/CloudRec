package com.alipay.application.service.rule.enums;


/*
 *@title EffectRuleType
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/11 11:09
 */
public enum EffectRuleType {

    DEFAULT("default", "默认规则"),
    SELECTED("selected", "租户自选规则"),
    ALL("all", "全部");

    private final String code;
    private final String description;
    EffectRuleType(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}

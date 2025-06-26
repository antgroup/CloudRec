package com.alipay.application.service.rule.enums;


/*
 *@title Field
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/17 12:04
 */
public enum Field {

    ResourceId("ResourceId"),
    ResourceName("ResourceName"),
    PublicIp("PublicIp"),
    Region("Region"),
    ;

    private final String fieldName;

    Field(String fieldName) {
        this.fieldName = fieldName;
    }

    public String getFieldName() {
        return fieldName;
    }
}

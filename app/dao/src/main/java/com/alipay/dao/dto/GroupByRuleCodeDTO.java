package com.alipay.dao.dto;


import lombok.Getter;
import lombok.Setter;

/*
 *@title GroupByRuleCodeDTO
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/8/18 15:21
 */
@Getter
@Setter
public class GroupByRuleCodeDTO {

    private String ruleCode;

    private String ruleName;

    private Integer count;

    private String platform;
}

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alipay.application.service.rule;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alipay.application.share.request.rule.WhitedRuleConfigDTO;
import com.alipay.dao.po.RuleScanResultPO;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Date: 2025/3/18
 * Author: lz
 * Description: 使用普通规则引擎方式扫描白名单
 */

@Component
public class WhitedRuleEngineMatcher {


    public boolean matchRule(WhitedRuleConfigDTO rule, Map<String,String> risk) {
        String key = rule.getKey();
        String operator = rule.getOperator().name();
        String value = rule.getValue().toString().trim();

        if (!risk.containsKey(key)) {
            return false;
        }


        String riskValue = risk.get(key).trim();

        switch (operator) {
            case "EQ":
                return riskValue.equals(value);
            case "NE":
                return !riskValue.equals(value);
            case "LIKE":
                return riskValue.contains(value);
            case "NOT_LIKE":
                return !riskValue.contains(value);
            case "IN":
                return isIn(riskValue, value);
            case "NOT_IN":
                return !isIn(riskValue, value);
            default:
                return false;
        }
    }

    private boolean isIn(String riskValue, String values) {
        String[] valueArray = values.split(",");
        for (String value : valueArray) {
            if (riskValue.trim().equals(value.trim())) {
                return true;
            }
        }
        return false;
    }

    public boolean matchWhitelistRule(List<WhitedRuleConfigDTO> ruleConfiglist, String condition,  RuleScanResultPO ruleScanResultPO) {
        Map<String, String> risk = convertObjectToMap(ruleScanResultPO);
        if(CollectionUtils.isEmpty(ruleConfiglist)){
            return true;
        }
        Map<Integer, Boolean> resultsMap = new HashMap<>();
        for (WhitedRuleConfigDTO ruleConfig : ruleConfiglist) {
            boolean result = matchRule(ruleConfig, risk);
            resultsMap.put(ruleConfig.getId(), result);
        }
        return evaluateCondition(condition, resultsMap);
    }

    private boolean evaluateCondition(String condition, Map<Integer, Boolean> resultsMap) {
        return ExpressionEvaluator.evalExpression(condition, resultsMap);
    }


    public Map<String, String> convertObjectToMap(Object obj) {
        if (obj == null) {
            return null;
        }
        String jsonString = JSON.toJSONString(obj);

        JSONObject jsonObject = JSON.parseObject(jsonString);
        Map<String, String> resultMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
            if (entry.getValue() != null) {
                resultMap.put(entry.getKey(), entry.getValue().toString());
            } else {
                resultMap.put(entry.getKey(), null);
            }
        }
        return resultMap;
    }
}

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
import com.alipay.application.service.risk.engine.ConditionItem;
import com.alipay.application.service.risk.engine.Fact;
import com.alipay.application.service.risk.engine.Operator;
import com.alipay.application.service.risk.engine.handler.OperatorHandlerComplete;
import com.alipay.application.share.request.rule.WhitedRuleConfigDTO;
import com.alipay.dao.po.RuleScanResultPO;
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


    /**
     * Match rule using unified rule engine architecture
     * @param rule the rule configuration to match
     * @param risk the risk data map
     * @return true if the rule matches
     */
    public boolean matchRule(WhitedRuleConfigDTO rule, Map<String,String> risk) {
        if (rule == null || risk == null) {
            return false;
        }
        
        String key = rule.getKey();
        if (key == null) {
            return false;
        }
        
        Operator operator = convertToOperator(rule.getOperator());
        Object value = rule.getValue();
        
        // Handle IN and NOT_IN operators - convert comma-separated string to List
        if ((operator == Operator.IN || operator == Operator.NOT_IN) && value instanceof String) {
            String stringValue = value.toString().trim();
            if (!stringValue.isEmpty()) {
                value = List.of(stringValue.split(","));
            }
        } else if (value != null) {
            value = value.toString().trim();
        }

        if (!risk.containsKey(key)) {
            return false;
        }

        String riskValue = risk.get(key);
        if (riskValue != null) {
            riskValue = riskValue.trim();
        }

        // Create condition item and fact for unified rule engine
        ConditionItem conditionItem = new ConditionItem(operator, key, value);
        Fact fact = new Fact(key, riskValue);
        List<Fact> facts = List.of(fact);

        // Use unified rule engine handler
        return OperatorHandlerComplete.handle(conditionItem, facts);
    }

    /**
     * Convert WhitedRuleOperatorEnum to Operator
     * @param whitedOperator the whited rule operator
     * @return corresponding Operator enum
     */
    private Operator convertToOperator(com.alipay.common.enums.WhitedRuleOperatorEnum whitedOperator) {
        switch (whitedOperator) {
            case EQ:
                return Operator.EQ;
            case NE:
                return Operator.NE;
            case LIKE:
                return Operator.LIKE;
            case NOT_LIKE:
                return Operator.NOT_LIKE;
            case IN:
                return Operator.IN;
            case NOT_IN:
                return Operator.NOT_IN;
            default:
                throw new RuntimeException("Unsupported operator: " + whitedOperator);
        }
    }



    public boolean matchWhitelistRule(List<WhitedRuleConfigDTO> ruleConfiglist, String condition,  RuleScanResultPO ruleScanResultPO) {
        Map<String, String> risk = convertObjectToMap(ruleScanResultPO);
        if(ruleConfiglist == null){
            return false;
        }
        if(ruleConfiglist.isEmpty()){
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

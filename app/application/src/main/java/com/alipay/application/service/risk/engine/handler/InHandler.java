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
package com.alipay.application.service.risk.engine.handler;

import com.alipay.application.service.risk.engine.ConditionItem;
import com.alipay.application.service.risk.engine.Fact;
import com.alipay.application.service.risk.engine.Operator;
import java.util.List;

/**
 * Handler for IN operator
 * Checks if the fact value is in the comma-separated list of condition values
 */
public class InHandler extends AbstractHanlder {

    /**
     * Check if this handler can handle the given condition
     * @param conditionItem the condition item to check
     * @return true if this handler can handle IN operator
     */
    @Override
    protected boolean canHandle(ConditionItem conditionItem) {
        return conditionItem.getOperator() == Operator.IN;
    }

    /**
     * Handle the IN operation
     * @param conditionItem the condition item containing the comma-separated values
     * @param fact the fact to check against
     * @return true if the fact value is in the condition values list
     */
    @Override
    protected boolean doHandle(ConditionItem conditionItem, Fact fact) {
        Object conditionValue = conditionItem.getValue();
        Object factValue = fact.getValue();
        
        if (conditionValue == null || factValue == null) {
            return false;
        }
        
        String factStr = factValue.toString().trim();
        
        // Handle List type (from WhitedRuleEngineMatcher)
        if (conditionValue instanceof List) {
            List<?> valueList = (List<?>) conditionValue;
            for (Object value : valueList) {
                if (value != null && factStr.equals(value.toString().trim())) {
                    return true;
                }
            }
            return false;
        }
        
        // Handle String type (comma-separated values)
        String conditionStr = conditionValue.toString();
        String[] valueArray = conditionStr.split(",");
        for (String value : valueArray) {
            if (factStr.equals(value.trim())) {
                return true;
            }
        }
        
        return false;
    }
}
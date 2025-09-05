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
 * Handler for NE (Not Equal) operator
 * Checks if the fact value is not equal to the condition value
 */
public class NeHandler extends AbstractHanlder {

    /**
     * Check if this handler can handle the given condition
     * @param conditionItem the condition item to check
     * @return true if this handler can handle NE operator
     */
    @Override
    protected boolean canHandle(ConditionItem conditionItem) {
        return conditionItem.getOperator() == Operator.NE;
    }

    /**
     * Handle the NE operation
     * @param conditionItem the condition item containing the expected value
     * @param fact the fact to check against
     * @return true if the fact value is not equal to the condition value
     */
    @Override
    protected boolean doHandle(ConditionItem conditionItem, Fact fact) {
        Object conditionValue = conditionItem.getValue();
        Object factValue = fact.getValue();
        
        if (conditionValue == null && factValue == null) {
            return false; // Both null, they are equal, so NE returns false
        }
        
        if (conditionValue == null || factValue == null) {
            return true; // One is null, the other is not, so they are not equal
        }
        
        // Convert both to strings for comparison
        String conditionStr = conditionValue.toString().trim();
        String factStr = factValue.toString().trim();
        
        return !conditionStr.equals(factStr);
    }
}
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
package com.alipay.application.service.risk.engine;

import lombok.Getter;

import java.util.List;

@Getter
public class Condition {

    protected Operator operator;

    private List<Condition> subConditions;

    protected Condition(Operator operator) {
        this.operator = operator;
    }

    public Condition(Operator operator, List<Condition> subConditions) {
        this.operator = operator;
        this.subConditions = subConditions;
    }

    /**
     * Evaluates the condition against the provided facts.
     * For composite conditions (ANY/ALL), evaluates all sub-conditions.
     * For leaf conditions, this method should be overridden by subclasses.
     * 
     * @param facts List of facts to evaluate against
     * @return true if the condition matches, false otherwise
     */
    public boolean match(List<Fact> facts) {
        // For leaf conditions without sub-conditions, return false by default
        // This should be overridden by subclasses like ConditionItem
        return false;
    }
}

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

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
public class JsonRuleEngine {


    public static JsonRule parseOne(String jsonString) {
        try {
            return parseOne(JSON.parseObject(jsonString));
        } catch (Exception e) {
            log.error("parseOne jsonString error", e);
        }
        return null;
    }

    public static JsonRule parseOne(JSONObject jsonObject) {
        try {
            JSONObject conditionJson = jsonObject.getJSONObject("condition");

            Condition condition;
            if (conditionJson != null && (condition = parseCondition(conditionJson)) != null) {
                return new JsonRule(condition);
            }
        } catch (Exception e) {
            log.error("parseOne jsonObject error", e);
        }
        return null;
    }

    private static Condition parseCondition(JSONObject jsonObject) {
        try {
            List<String> keys = new ArrayList<>(jsonObject.keySet());
            if (keys.size() == 1) {
                List<Condition> subConditions = jsonObject.getJSONArray(keys.get(0)).stream()
                        .map(o -> parseCondition((JSONObject) o)).filter(Objects::nonNull).collect(Collectors.toList());
                return new Condition(Operator.valueOf(keys.get(0)), subConditions);
            } else {
                return new ConditionItem(Operator.valueOf(jsonObject.getString("operator")),
                        jsonObject.getString("key"), jsonObject.get("value"));
            }
        } catch (Exception e) {
            log.error("parseCondition jsonObject error", e);
        }
        return null;
    }
}

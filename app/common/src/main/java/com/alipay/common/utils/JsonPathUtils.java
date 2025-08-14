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
package com.alipay.common.utils;


/*
 *@title JsonPathUtils
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/4/11 16:19
 */

import com.alibaba.fastjson.JSON;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import com.jayway.jsonpath.spi.json.JacksonJsonProvider;
import com.jayway.jsonpath.spi.mapper.JacksonMappingProvider;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JsonPathUtils {

    // 配置 Fastjson 作为 JSON 解析器（提升性能）
    private static final Configuration JACKSON_CONFIG = Configuration.builder()
            .jsonProvider(new JacksonJsonProvider())
            .mappingProvider(new JacksonMappingProvider())
            .build();

    /**
     * 从 JSON 字符串中提取值（自动推断类型）
     *
     * @param json     JSON 字符串
     * @param jsonPath JSONPath 表达式
     * @return 原始对象（需自行处理类型转换）
     */
    public static Object getValue(String json, String jsonPath) {
        try {
            return JsonPath.using(JACKSON_CONFIG).parse(json).read(jsonPath);
        } catch (PathNotFoundException e) {
            log.debug("JSONPath [{}] not found", jsonPath);
            return null;
        } catch (Exception e) {
            log.error("JSONPath extraction failed: {}", jsonPath, e);
            return null;
        }
    }

    /**
     * 安全提取并转换为指定类型
     *
     * @param json     JSON 字符串
     * @param jsonPath JSONPath 表达式
     * @param clazz    目标类型
     * @return 转换后的对象，失败时返回 null
     */
    public static <T> T getValue(String json, String jsonPath, Class<T> clazz) {
        try {
            Object value = getValue(json, jsonPath);
            return value == null ? null : JSON.parseObject(JSON.toJSONString(value), clazz);
        } catch (Exception e) {
            log.error("Type conversion failed for JSONPath: {}", jsonPath, e);
            return null;
        }
    }
}

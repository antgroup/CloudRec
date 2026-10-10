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
package com.alipay.application.service.rule.domain.repo;

import com.alipay.application.service.rule.domain.repo.factory.RuleFactoryImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class LocalRuleCompatibilityTest {
    @TempDir Path directory;

    @Test
    void loadsJsonMetadataUtf8PolicyAndRelatedVariablesWithoutNetwork() throws Exception {
        Path rule = directory.resolve("rules/local/example");
        Path data = directory.resolve("rules/data");
        Files.createDirectories(rule);
        Files.createDirectories(data);
        Files.writeString(rule.resolve("metadata.json"), """
                {"platform":"ALI_CLOUD","resourceType":"ECS","code":"local_rule",
                 "name":"本地规则","description":"本地兼容测试","level":"High",
                 "categoryList":["test"],"advice":"placeholder"}
                """, StandardCharsets.UTF_8);
        String policy = "package local_rule\n# 本地规则\ndefault risk := false\n";
        Files.writeString(rule.resolve("policy.rego"), policy, StandardCharsets.UTF_8);
        Files.writeString(rule.resolve("relation.json"), "[\"allowed_regions\"]", StandardCharsets.UTF_8);
        Files.writeString(data.resolve("regions.json"), "{\"allowed_regions\":[\"local-test\"]}", StandardCharsets.UTF_8);
        RuleRepositoryImpl repository = new RuleRepositoryImpl();
        ReflectionTestUtils.setField(repository, "rulePath", directory.toString());
        ReflectionTestUtils.setField(repository, "ruleFactory", new RuleFactoryImpl());
        var rules = repository.findRuleListFromLocalFile();
        assertEquals(1, rules.size());
        var loaded = rules.get(0);
        assertEquals("local_rule", loaded.getRuleCode());
        assertEquals("本地规则", loaded.getRuleName());
        assertEquals(policy, loaded.getRegoPolicy());
        assertEquals("[\"local-test\"]", loaded.getGlobalVariables().get(0).getData());
        assertEquals("valid", loaded.getGlobalVariables().get(0).getStatus());
    }
}

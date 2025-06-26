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
package com.alipay.application.service.rule.domain.repo.factory;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alipay.application.service.rule.domain.GlobalVariable;
import com.alipay.application.service.rule.domain.RuleAgg;
import com.alipay.common.utils.Util;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class RuleExporter {

    /**
     * 生成规则文件
     *
     * @param rules 规则列表
     */
    public String generateRulesFile(List<RuleAgg> rules) {
        RuleFactory ruleFactory = new RuleFactoryImpl();
        String tempRootDir = System.getProperty("java.io.tmpdir") + "/cloudrec_" + System.currentTimeMillis();
        String tempGlobalVarDir = tempRootDir + "/" + MetadataParser.GLOBAL_VARIABLE;
        try {
            Files.createDirectories(new File(tempGlobalVarDir).toPath());
        } catch (IOException e) {
            log.warn("Unable to create temp directory:{} ", tempGlobalVarDir);
            return null;
        }

        for (RuleAgg rule : rules) {
            String rulePath = tempRootDir + "/" + MetadataParser.RULE_FILE_NAME + rule.getPlatform() + "/" + rule.getRuleCode() + "/";
            try {
                Files.createDirectories(new File(rulePath).toPath());
                writeTextFile(rulePath + "metadata.json", JSON.toJSONString(ruleFactory.convertToMetadata(rule), SerializerFeature.WriteMapNullValue));
                writeTextFile(rulePath + "policy.rego", rule.getRegoPolicy());
                writeTextFile(rulePath + "input.json", rule.getExampleResourceData());
                writeTextFile(rulePath + "relation.json", JSON.toJSONString(Util.map(rule.getGlobalVariables(), GlobalVariable::getPath)));
            } catch (IOException e) {
                log.warn("Error processing rule {}", rule.getRuleCode());
            }

            // Handle rule-related global variable writing
            if (rule.getGlobalVariables() != null && !rule.getGlobalVariables().isEmpty()) {
                for (GlobalVariable variable : rule.getGlobalVariables()) {
                    try {
                        String dataFilePath = tempGlobalVarDir + "/" + variable.getPath() + ".json";
                        Map<String, Object> map = new HashMap<>();
                        map.put(variable.getPath(), JSON.parse(variable.getData()));
                        writeTextFile(dataFilePath, JSON.toJSONString(map, SerializerFeature.WriteMapNullValue));
                        log.info("Successfully written to global variable file: {}", dataFilePath);
                    } catch (Exception e) {
                        log.warn("Error processing global variable {}", variable.getPath());
                    }
                }
            }
        }
        return tempRootDir;
    }


    private void writeJsonFile(String path, String content) throws IOException {
        Path filePath = Paths.get(path);
        if (Files.exists(filePath)) {
            log.warn("The file already exists, perform the overwrite operation: {}", path);
        }
        Files.writeString(filePath, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private void writeTextFile(String path, String content) throws IOException {
        if (content == null) {
            content = "[]";
        }
        try (BufferedWriter writer = Files.newBufferedWriter(
                new File(path).toPath(),
                StandardCharsets.UTF_8)) {
            writer.write(content);
        }
    }
}
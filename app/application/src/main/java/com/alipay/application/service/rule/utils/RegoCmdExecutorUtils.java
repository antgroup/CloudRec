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
package com.alipay.application.service.rule.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.PumpStreamHandler;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/*
 *@title RegoLintExecutor
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/7/26 15:52
 */
@Slf4j
public class RegoCmdExecutorUtils {

    @Data
    public static class RegoCmdExecutorResponse {
        private List<Lint> lintResult;

        private String fixResult;

        private String errMsg;

        public RegoCmdExecutorResponse() {
        }

        public RegoCmdExecutorResponse(List<Lint> lintResult, String fixResult) {
            this.lintResult = lintResult;
            this.fixResult = fixResult;
        }
    }

    public static RegoCmdExecutorResponse executeRegoCmd(String regoPolicy) {
        File tempFile = null;
        try {
            tempFile = File.createTempFile(UUID.randomUUID().toString(), ".rego");
            try (OutputStream os = new FileOutputStream(tempFile)) {
                os.write(regoPolicy.getBytes(StandardCharsets.UTF_8));
            }

            String lintResp = executeRegoLintCmd(tempFile);
            List<Lint> lints = Lint.extractLintObjects(lintResp);
            String fixResp = executeRegoFixCmd(tempFile);

            return new RegoCmdExecutorResponse(lints, fixResp);
        } catch (IOException e) {
            log.error("IO Error: {}", e.getMessage(), e);
        } finally {
            if (tempFile != null && tempFile.exists()) {
                boolean delete = tempFile.delete();
                if (!delete) {
                    log.warn("Failed to delete temp file:{}", tempFile.getAbsolutePath());
                }
            }
        }

        return new RegoCmdExecutorResponse();
    }

    /**
     * 执行Rego命令
     *
     * @param file Rego规则文件
     * @return Rego规则文件的内容
     */
    private static String executeRegoLintCmd(File file) {
        // Build the command line
        CommandLine cmdLine = new CommandLine("regal");
        cmdLine.addArgument("lint");
        cmdLine.addArgument(file.getAbsolutePath());
        log.info("file path>>>>>:{}", file.getAbsolutePath());

        DefaultExecutor executor = DefaultExecutor.builder().get();
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        executor.setStreamHandler(new PumpStreamHandler(stdout, stderr));

        try {
            executor.execute(cmdLine);
        } catch (IOException e) {
            log.warn("ExecuteException: {}", e.getMessage());
        }

        return stdout.toString(StandardCharsets.UTF_8);
    }


    private static String executeRegoFixCmd(File file) throws IOException {
        // Build the command line
        CommandLine cmdLine = new CommandLine("regal");
        cmdLine.addArgument("fix");
        cmdLine.addArgument(file.getAbsolutePath());

        DefaultExecutor executor = DefaultExecutor.builder().get();
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        executor.setStreamHandler(new PumpStreamHandler(stdout, stderr));

        // Run the command and wait for the result
        try {
            executor.execute(cmdLine);
        } catch (IOException e) {
            // Handle non-zero exit values
            log.warn("ExecuteException: {}", e.getMessage());
        }

        // Return the stdout content
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        StringBuilder content = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        return content.toString();
    }

    @Data
    public static class Lint {
        private String rule;
        private String description;
        private String category;
        private String location;
        private String text;
        private String documentation;

        // Constructor
        public Lint(String rule, String description, String category, String location, String text,
                    String documentation) {
            this.rule = rule;
            this.description = description;
            this.category = category;
            this.location = location;
            this.text = text;
            this.documentation = documentation;
        }

        // Main method to extract lint objects from the text
        public static List<Lint> extractLintObjects(String inputText) {
            List<Lint> lintList = new ArrayList<>();

            // Split the input text into individual lint blocks
            String[] lintBlocks = inputText.split("Rule:");

            // Skip the first element of the lintBlocks array as it will be empty
            for (int i = 1; i < lintBlocks.length; i++) {
                String[] lines = lintBlocks[i].trim().split("\n");
                String rule = "";
                String description = "";
                String category = "";
                String location = "";
                String text = "";
                String documentation = "";

                // Extract the properties from the lines
                for (String line : lines) {
                    if (line.contains("Description:")) {
                        description = line.split("Description:")[1].trim();
                    } else if (line.contains("Category:")) {
                        category = line.split("Category:")[1].trim();
                    } else if (line.contains("Location:")) {
                        location = line.split("Location:")[1].trim().split("\\.")[1].trim();
                    } else if (line.contains("Text:")) {
                        text = line.split("Text:")[1].trim();
                    } else if (line.contains("Documentation:")) {
                        documentation = line.split("Documentation:")[1].trim();
                    } else {
                        rule = line.trim();
                    }
                }

                // Create a new Lint object and add it to the lintList
                lintList.add(new Lint(rule, description, category, location, text, documentation));
            }

            return lintList;
        }
    }
}

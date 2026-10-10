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
package com.alipay.bootstrap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.status.Status;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class LogbackCompatibilityTest {
    @TempDir Path directory;

    @Test
    void loadsRollsAndReloadsExistingXmlConfigurations() throws Exception {
        for (String resource : new String[]{"logback.xml", "logback-spring.xml"}) {
            String xml;
            try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
                assertNotNull(input);
                xml = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            }
            xml = xml.replace("value=\"logs\"", "value=\"" + directory + "\"")
                    .replace("/tmp/cloudrec.log", directory.resolve("cloudrec.log").toString())
                    .replace("250MB", "1KB");
            Path config = directory.resolve(resource);
            Files.writeString(config, xml);
            LoggerContext context = new LoggerContext();
            context.setMDCAdapter(new ch.qos.logback.classic.util.LogbackMDCAdapter());
            try {
                context.start();
                configure(context, config);
                assertTrue(context.getStatusManager().getCopyOfStatusList().stream().noneMatch(s -> s.getLevel() == Status.ERROR),
                        context.getStatusManager().getCopyOfStatusList().toString());
                context.getLogger("ROOT").detachAppender("CONSOLE");
                context.getLogger("ROOT").detachAppender("console");
                var logger = context.getLogger("compatibility");
                for (int i = 0; i < 80; i++) logger.info("local-test-" + "x".repeat(2048));
                if (resource.equals("logback.xml")) {
                    assertTrue(Files.exists(directory.resolve("log_info.log")));
                    try (var paths = Files.walk(directory)) {
                        assertTrue(paths.anyMatch(p -> p.getFileName().toString().startsWith("info-")), "size rollover did not produce an archive");
                    }
                }
                Files.writeString(config, xml.replace("<root level=\"INFO\">", "<root level=\"WARN\">")
                        .replace("<root level=\"info\">", "<root level=\"WARN\">"));
                if (resource.equals("logback-spring.xml")) {
                    long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
                    while (context.getLogger("ROOT").getLevel() != Level.WARN && System.nanoTime() < deadline) {
                        Thread.sleep(100);
                    }
                } else {
                    context.reset();
                    configure(context, config);
                }
                assertEquals(Level.WARN, context.getLogger("ROOT").getLevel());
            } finally {
                context.stop();
            }
        }
    }

    private void configure(LoggerContext context, Path path) throws Exception {
        JoranConfigurator configurator = new JoranConfigurator();
        configurator.setContext(context);
        configurator.doConfigure(path.toFile());
    }
}

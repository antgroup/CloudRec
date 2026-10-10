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
package com.alipay.api.config.filter;

import com.alipay.api.config.MessageConfig;
import com.alipay.api.config.handler.GlobalExceptionHandler;
import com.alipay.dao.mapper.UserMapper;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/** Starts embedded Tomcat with the application's MVC configuration and interceptors. */
@SpringBootTest(classes = WebCompatibilityTest.Config.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"server.address=127.0.0.1", "spring.main.banner-mode=off"})
class WebCompatibilityTest {
    @LocalServerPort int port;
    private final ObjectMapper json = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder().cookieHandler(new CookieManager()).build();

    private HttpResponse<String> get(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void servesJsonAndClasspathStaticResource() throws Exception {
        assertEquals("ok", json.readTree(get("/public/probe").body()).get("status").asText());
        var resource = get("/dependency-smoke.txt");
        assertEquals(200, resource.statusCode());
        assertEquals("local-static-probe", resource.body().trim());
    }

    @Test
    void keepsPermissionInterceptorAndSessionBehavior() throws Exception {
        var rejected = json.readTree(get("/api/dependency/probe").body());
        assertEquals(401, rejected.get("code").asInt());
        assertEquals("USER_NOT_LOGIN", rejected.get("content").asText());
        assertEquals("1", get("/public/session").body());
        assertEquals("2", get("/public/session").body());
    }

    @Test
    void disallowedFieldRemainsProtectedUnderTurkishLocale() throws Exception {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            var body = json.readTree(get("/public/form?id=attempt&name=allowed").body());
            assertTrue(body.get("id").isNull());
            assertEquals("allowed", body.get("name").asText());
        } finally {
            Locale.setDefault(original);
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration(excludeName = {
            "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration",
            "org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration",
            "org.mybatis.spring.boot.autoconfigure.MybatisAutoConfiguration"})
    @Import({WebMvcConfig.class, MessageConfig.class, PermissionInterceptor.class, OpenApiInterceptor.class,
            LangContextInterceptor.class, GlobalExceptionHandler.class, Probe.class})
    static class Config {
        @Bean UserMapper userMapper() { return mock(UserMapper.class); }
    }

    @RestController
    static class Probe {
        @GetMapping({"/public/probe", "/api/dependency/probe"})
        Map<String, String> probe() { return Map.of("status", "ok"); }
        @GetMapping("/public/session")
        String session(HttpSession session) {
            Integer previous = (Integer) session.getAttribute("counter");
            int next = previous == null ? 1 : previous + 1;
            session.setAttribute("counter", next);
            return Integer.toString(next);
        }
        @InitBinder("form")
        void protect(WebDataBinder binder) { binder.setDisallowedFields("ID"); }
        @GetMapping("/public/form")
        Form form(@ModelAttribute("form") Form form) { return form; }
    }

    public static class Form {
        private String id;
        private String name;
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }
}

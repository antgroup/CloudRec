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

import com.alibaba.druid.pool.DruidDataSource;
import com.alipay.dao.config.DataConfig;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Properties;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/** Runs only against an explicitly configured, disposable loopback database. */
@EnabledIfEnvironmentVariable(named = "CLOUDREC_TEST_JDBC_URL", matches = ".+")
class JdbcCompatibilityTest {
    private String url;
    private String username;
    private String password;
    private String port;

    @BeforeEach
    void configuration() {
        url = System.getenv("CLOUDREC_TEST_JDBC_URL");
        var matcher = Pattern.compile("jdbc:mariadb://(localhost|127\\.0\\.0\\.1):([0-9]+)/cloudrec_dependency_test(\\?.*)?").matcher(url);
        assertTrue(matcher.matches(),
                "Use a disposable loopback database named cloudrec_dependency_test");
        port = matcher.group(2);
        username = System.getenv("CLOUDREC_TEST_JDBC_USER");
        password = System.getenv("CLOUDREC_TEST_JDBC_PASSWORD");
    }

    private DruidDataSource pool() {
        return pool(url, "org.mariadb.jdbc.Driver");
    }

    private DruidDataSource pool(String jdbcUrl, String driver) {
        DataConfig config = new DataConfig();
        ReflectionTestUtils.setField(config, "driver", driver);
        ReflectionTestUtils.setField(config, "url", jdbcUrl);
        ReflectionTestUtils.setField(config, "username", username);
        ReflectionTestUtils.setField(config, "password", password);
        DruidDataSource source = (DruidDataSource) config.dataSource();
        source.setMaxWait(3000);
        source.setBreakAfterAcquireFailure(true);
        return source;
    }

    @Test
    void poolQueriesPaginationTransactionsAndReconnect() throws Exception {
        try (DruidDataSource source = pool()) {
            source.init();
            JdbcTemplate jdbc = new DataConfig().jdbcTemplate(source);
            jdbc.execute("DROP TABLE IF EXISTS dependency_smoke");
            jdbc.execute("CREATE TABLE dependency_smoke (id INT AUTO_INCREMENT PRIMARY KEY, value_text VARCHAR(100), instant_value TIMESTAMP(6), local_value DATETIME(6))");
            jdbc.update("INSERT INTO dependency_smoke (id, value_text) VALUES (?, ?)", 1, "你好🌏");
            jdbc.update("INSERT INTO dependency_smoke (id, value_text) VALUES (?, ?)", 2, "second");
            assertEquals("你好🌏", jdbc.queryForObject("SELECT value_text FROM dependency_smoke WHERE id = ?", String.class, 1));
            assertEquals("+08:00", jdbc.queryForObject("SELECT @@session.time_zone", String.class));
            assertFalse(jdbc.queryForMap("SHOW SESSION STATUS LIKE 'Ssl_cipher'").get("Value").toString().isBlank());

            Instant instant = Instant.parse("2026-10-10T00:00:00.123456Z");
            LocalDateTime local = LocalDateTime.of(2026, 10, 10, 12, 30, 0, 123456000);
            jdbc.update("UPDATE dependency_smoke SET instant_value = ?, local_value = ? WHERE id = 1",
                    Timestamp.from(instant), local);
            assertEquals(instant, jdbc.queryForObject("SELECT instant_value FROM dependency_smoke WHERE id = 1", Timestamp.class).toInstant());
            assertEquals("2026-10-10 08:00:00.123456", jdbc.queryForObject("SELECT CAST(instant_value AS CHAR) FROM dependency_smoke WHERE id = 1", String.class));
            assertEquals(local, jdbc.queryForObject("SELECT local_value FROM dependency_smoke WHERE id = 1", LocalDateTime.class));

            Configuration mybatis = new Configuration(new Environment("local-test", new JdbcTransactionFactory(), source));
            mybatis.addMapper(SmokeMapper.class);
            try (var session = new SqlSessionFactoryBuilder().build(mybatis).openSession()) {
                assertEquals(List.of(2), session.getMapper(SmokeMapper.class).ids(new RowBounds(1, 1)));
            }

            TransactionTemplate tx = new TransactionTemplate(new DataSourceTransactionManager(source));
            tx.executeWithoutResult(status -> jdbc.update("INSERT INTO dependency_smoke (id, value_text) VALUES (3, 'committed')"));
            tx.executeWithoutResult(status -> {
                jdbc.update("INSERT INTO dependency_smoke (id, value_text) VALUES (4, 'rolled back')");
                status.setRollbackOnly();
            });
            assertEquals(3, jdbc.queryForObject("SELECT COUNT(*) FROM dependency_smoke", Integer.class));
            assertThrows(org.springframework.dao.DuplicateKeyException.class,
                    () -> jdbc.update("INSERT INTO dependency_smoke (id, value_text) VALUES (3, 'duplicate')"));
            assertEquals(1, jdbc.queryForObject("SELECT 1", Integer.class));

            SmokeRow generated = new SmokeRow();
            generated.setValueText("generated key");
            try (var session = new SqlSessionFactoryBuilder().build(mybatis).openSession(true)) {
                assertEquals(1, session.getMapper(SmokeMapper.class).insert(generated));
            }
            assertNotNull(generated.getId());
            assertTrue(generated.getId() > 3);
            assertEquals("generated key", jdbc.queryForObject("SELECT value_text FROM dependency_smoke WHERE id = ?", String.class, generated.getId()));

            try (var connection = source.getConnection()) {
                long connectionId;
                try (var statement = connection.createStatement();
                     var result = statement.executeQuery("SELECT CONNECTION_ID()")) {
                    assertTrue(result.next());
                    connectionId = result.getLong(1);
                }
                // Kill this pooled connection from a separate driver connection.
                try (var killer = DriverManager.getConnection(url, username, password);
                     var statement = killer.createStatement()) {
                    statement.execute("KILL " + connectionId);
                }
            }
            assertEquals(1, jdbc.queryForObject("SELECT 1", Integer.class));
            jdbc.execute("DROP TABLE dependency_smoke");
        }
    }

    @Test
    void rejectsBadAuthenticationAndUntrustedTlsPeer() {
        assertThrows(SQLException.class, () -> DriverManager.getConnection(url, username, "incorrect-local-password"));
        Properties properties = new Properties();
        properties.setProperty("user", username);
        properties.setProperty("password", password);
        properties.setProperty("sslMode", "verify-full");
        properties.setProperty("fallbackToSystemTrustStore", "false");
        String bareUrl = url.substring(0, url.indexOf('?'));
        assertThrows(SQLException.class, () -> DriverManager.getConnection(bareUrl, properties));

        // The disposable server certificate must cover localhost, but not the IP address.
        String ca = System.getenv("CLOUDREC_TEST_JDBC_CA");
        assertNotNull(ca, "Set CLOUDREC_TEST_JDBC_CA to the disposable server CA certificate");
        properties.setProperty("serverSslCert", ca);
        String wrongHostname = bareUrl.replace("//localhost:", "//127.0.0.1:");
        assertNotEquals(bareUrl, wrongHostname, "Use localhost in the verified-TLS test URL");
        assertThrows(SQLException.class, () -> DriverManager.getConnection(wrongHostname, properties));
    }

    @Test
    void configuredProfilesAuthenticateAndRejectLocalInfile(@TempDir Path directory) throws Exception {
        Path input = directory.resolve("local-infile.txt");
        Files.writeString(input, "must not load\n");
        for (String profile : List.of("application", "application-local", "application-opensource")) {
            Properties config = new Properties();
            try (var resource = getClass().getResourceAsStream("/config/" + profile + ".properties")) {
                assertNotNull(resource);
                config.load(resource);
            }
            String localUrl = config.getProperty("spring.datasource.url").replaceFirst(
                    "//[^/]+/cloudrec_db", "//localhost:" + port + "/cloudrec_dependency_test");
            try (DruidDataSource source = pool(localUrl, config.getProperty("spring.datasource.driver-class-name"))) {
                source.init();
                JdbcTemplate jdbc = new DataConfig().jdbcTemplate(source);
                assertEquals(1, jdbc.queryForObject("SELECT 1", Integer.class), profile);
                assertEquals("", jdbc.queryForMap("SHOW SESSION STATUS LIKE 'Ssl_cipher'").get("Value").toString(), profile);
                assertEquals(1, jdbc.queryForObject("SELECT @@global.local_infile", Integer.class),
                        "Enable LOCAL INFILE only on the disposable test server to exercise client rejection");
                jdbc.execute("DROP TABLE IF EXISTS dependency_infile");
                jdbc.execute("CREATE TABLE dependency_infile (value_text VARCHAR(100))");
                try (var connection = source.getConnection(); var statement = connection.createStatement()) {
                    assertThrows(SQLException.class, () -> statement.execute("LOAD DATA LOCAL INFILE '"
                            + input.toString().replace("'", "''") + "' INTO TABLE dependency_infile"), profile);
                }
                assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM dependency_infile", Integer.class), profile);
                jdbc.execute("DROP TABLE dependency_infile");
            }
        }
    }

    public interface SmokeMapper {
        @Select("SELECT id FROM dependency_smoke ORDER BY id")
        List<Integer> ids(RowBounds page);

        @Insert("INSERT INTO dependency_smoke (value_text) VALUES (#{valueText})")
        @Options(useGeneratedKeys = true, keyProperty = "id")
        int insert(SmokeRow row);
    }

    public static class SmokeRow {
        private Integer id;
        private String valueText;

        public Integer getId() { return id; }
        public void setId(Integer id) { this.id = id; }
        public String getValueText() { return valueText; }
        public void setValueText(String valueText) { this.valueText = valueText; }
    }
}

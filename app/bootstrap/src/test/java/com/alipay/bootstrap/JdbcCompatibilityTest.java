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
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/** Runs only against an explicitly configured, disposable loopback database. */
@EnabledIfEnvironmentVariable(named = "CLOUDREC_TEST_JDBC_URL", matches = ".+")
class JdbcCompatibilityTest {
    private String url;
    private String username;
    private String password;

    @BeforeEach
    void configuration() {
        url = System.getenv("CLOUDREC_TEST_JDBC_URL");
        assertTrue(url.matches("jdbc:mysql://(localhost|127\\.0\\.0\\.1):[0-9]+/cloudrec_dependency_test(\\?.*)?"),
                "Use a disposable loopback database named cloudrec_dependency_test");
        username = System.getenv("CLOUDREC_TEST_JDBC_USER");
        password = System.getenv("CLOUDREC_TEST_JDBC_PASSWORD");
    }

    private DruidDataSource pool() {
        DataConfig config = new DataConfig();
        ReflectionTestUtils.setField(config, "driver", "com.mysql.cj.jdbc.Driver");
        ReflectionTestUtils.setField(config, "url", url);
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
            jdbc.execute("CREATE TABLE dependency_smoke (id INT PRIMARY KEY, value_text VARCHAR(100))");
            jdbc.update("INSERT INTO dependency_smoke VALUES (?, ?)", 1, "你好");
            jdbc.update("INSERT INTO dependency_smoke VALUES (?, ?)", 2, "second");
            assertEquals("你好", jdbc.queryForObject("SELECT value_text FROM dependency_smoke WHERE id = ?", String.class, 1));
            assertEquals("Asia/Shanghai", jdbc.queryForObject("SELECT @@session.time_zone", String.class));
            assertFalse(jdbc.queryForMap("SHOW SESSION STATUS LIKE 'Ssl_cipher'").get("Value").toString().isBlank());

            Configuration mybatis = new Configuration(new Environment("local-test", new JdbcTransactionFactory(), source));
            mybatis.addMapper(SmokeMapper.class);
            try (var session = new SqlSessionFactoryBuilder().build(mybatis).openSession()) {
                assertEquals(List.of(2), session.getMapper(SmokeMapper.class).ids(new RowBounds(1, 1)));
            }

            TransactionTemplate tx = new TransactionTemplate(new DataSourceTransactionManager(source));
            tx.executeWithoutResult(status -> jdbc.update("INSERT INTO dependency_smoke VALUES (3, 'committed')"));
            tx.executeWithoutResult(status -> {
                jdbc.update("INSERT INTO dependency_smoke VALUES (4, 'rolled back')");
                status.setRollbackOnly();
            });
            assertEquals(3, jdbc.queryForObject("SELECT COUNT(*) FROM dependency_smoke", Integer.class));
            assertThrows(org.springframework.dao.DuplicateKeyException.class,
                    () -> jdbc.update("INSERT INTO dependency_smoke VALUES (3, 'duplicate')"));
            assertEquals(1, jdbc.queryForObject("SELECT 1", Integer.class));

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
        properties.setProperty("sslMode", "VERIFY_IDENTITY");
        properties.setProperty("fallbackToSystemTrustStore", "false");
        String bareUrl = url.substring(0, url.indexOf('?'));
        assertThrows(SQLException.class, () -> DriverManager.getConnection(bareUrl, properties));
    }

    public interface SmokeMapper {
        @Select("SELECT id FROM dependency_smoke ORDER BY id")
        List<Integer> ids(RowBounds page);
    }
}

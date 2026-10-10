# JDBC compatibility checks

The server uses MariaDB Connector/J 3.5.10 with the existing MySQL 8.0 database. Java 17 and Maven 3.9 are required for the checks below.

Use a disposable MySQL 8.0.40 instance on a loopback port with a database named `cloudrec_dependency_test`. Import the public `db/init.sql` into this test database, replacing `cloudrec_db` with `cloudrec_dependency_test` in the fixture, including its `USE` statement. Keep all fixture edits outside the checkout. The application database, production credentials and cloud accounts must not be used for these tests.

Configure the disposable server with `caching_sha2_password`, UTF-8 (`utf8mb4`), a session default time zone of `+08:00`, and `local_infile=ON`. The last setting is needed only to verify that the application driver rejects local file loading. MySQL time zone tables can remain empty. Give a temporary test user access only to this test database.

For the TLS checks, configure the test server with a certificate issued by a disposable CA. Its subject alternative name must contain `DNS:localhost` and must not contain `127.0.0.1`. This allows testing both a trusted connection and rejection of the wrong peer identity against the same server.

Set the following environment variables, replacing the port, CA path and temporary credentials:

```sh
export CLOUDREC_TEST_JDBC_URL='jdbc:mariadb://localhost:13306/cloudrec_dependency_test?sslMode=verify-full&serverSslCert=/path/to/disposable-ca.pem&connectionTimeZone=Asia/Shanghai&preserveInstants=true&allowLocalInfile=false'
export CLOUDREC_TEST_JDBC_USER='cloudrec_test'
export CLOUDREC_TEST_JDBC_PASSWORD='temporary-test-password'
export CLOUDREC_TEST_JDBC_CA='/path/to/disposable-ca.pem'

mvn -pl app/bootstrap -am -Dmaven.test.skip=false -Duser.timezone=UTC \
  -Dtest=JdbcCompatibilityTest -Dsurefire.failIfNoSpecifiedTests=false test
```

The test class skips when the test URL is absent. It rejects non-loopback URLs and database names other than `cloudrec_dependency_test` before opening a connection. Run without parallel test execution because the cases share disposable fixture tables. To exercise a full non-TLS `caching_sha2_password` handshake rather than its cached fast path, clear the authentication cache on the disposable server and run the `configuredProfilesAuthenticateAndRejectLocalInfile` method alone.

The checks cover Druid initialization and reconnect, MyBatis pagination and generated keys, commit and rollback, duplicate-key translation, Unicode, timestamp instants, local date-time values, the three supplied application profiles, bad credentials, certificate trust, hostname verification, and disabled `LOAD DATA LOCAL INFILE`. Successful local checks do not establish compatibility with untested RDS or OceanBase configurations.

The accepted upstream limitation [CONJ-1345](https://jira.mariadb.org/browse/CONJ-1345) remains in 3.5.10: metadata URLs may contain passwords. These tests do not log `DatabaseMetaData.getURL()` or establish that all downstream metadata consumers redact credentials.

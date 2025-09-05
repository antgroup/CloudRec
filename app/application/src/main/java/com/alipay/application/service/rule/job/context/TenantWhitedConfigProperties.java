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
package com.alipay.application.service.rule.job.context;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for TenantWhitedConfigContext cache management
 * Provides configurable parameters for cache behavior, query pagination, and monitoring
 *
 * Date: 2025/1/17
 * Author: Assistant
 */
@Data
@Component
@ConfigurationProperties(prefix = "tenant.whited.config")
public class TenantWhitedConfigProperties {

    /**
     * Cache expiration time in milliseconds
     * Default: 5 min
     */
    private Long cacheExpirationTimeMs = 5 * 60 * 1000L;

    /**
     * Maximum number of entries in cache
     * Default: 100 entries
     */
    private Integer maxCacheSize = 10000;

    /**
     * Page size for database queries
     * Default: 100 records per page
     */
    private Integer queryPageSize = 100;

    /**
     * Maximum number of pages to query (prevents infinite loops)
     * Default: 1000 pages
     */
    private Integer maxQueryPages = 1000;

    /**
     * Enable cache statistics logging
     * Default: false
     */
    private boolean enableCacheStatsLogging = false;

    /**
     * Cache statistics logging interval in milliseconds
     * Default: 1 minute (60,000 ms)
     */
    private Long cacheStatsLoggingIntervalMs = 60 * 1000L;
}
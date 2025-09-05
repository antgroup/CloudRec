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

import com.alipay.application.service.rule.domain.repo.OpaRepository;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.common.enums.WhitedRuleTypeEnum;
import com.alipay.dao.dto.QueryWhitedRuleDTO;
import com.alipay.dao.mapper.WhitedRuleConfigMapper;
import com.alipay.dao.po.WhitedRuleConfigPO;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Tenant-isolated whited configuration context for managing whitelist configurations by tenant
 * This class provides caching mechanism to avoid repeated database queries for the same tenant
 *
 * Date: 2025/8/28
 */
@Slf4j
@Component
public class TenantWhitedConfigContextV2 {

    @Resource
    private WhitedRuleConfigMapper whitedRuleConfigMapper;

    @Resource
    private TenantRepository tenantRepository;

    @Resource
    private TenantWhitedConfigProperties configProperties;

    @Resource
    private OpaRepository opaRepository;

    /**
     * Caffeine cache for storing tenant-specific whitelisted rule configurations
     * Key: tenant ID, Value: List of WhitedRuleConfigPO objects
     * Caffeine provides high-performance caching with automatic expiration and size-based eviction
     */
    private Cache<Long, List<WhitedRuleConfigPO>> tenantConfigCache;

    /**
     * Initialize Caffeine cache with configuration from properties
     * This method is called after dependency injection is complete
     */
    @PostConstruct
    public void initializeCache() {
        this.tenantConfigCache = Caffeine.newBuilder()
                .maximumSize(configProperties.getMaxCacheSize())
                .expireAfterWrite(Duration.ofMillis(configProperties.getCacheExpirationTimeMs()))
                .recordStats() // Enable statistics for monitoring
                .build();

        log.info("Initialized Caffeine cache with maxSize: {}, expiration: {}ms",
                configProperties.getMaxCacheSize(), configProperties.getCacheExpirationTimeMs());
    }

    /**
     * Get whited rule configurations for a specific tenant with caching
     * Uses Caffeine cache for high-performance caching with automatic expiration
     * Implements exponential backoff retry mechanism to handle concurrent access issues
     *
     * @param tenantId the tenant ID to query configurations for
     * @return List of WhitedRuleConfigPO objects for the specified tenant
     */
    public List<WhitedRuleConfigPO> getWhitedConfigsByTenant(Long tenantId) {
        if (tenantId == null) {
            log.warn("Tenant ID is null, returning empty list");
            return new ArrayList<>();
        }

        // Use Caffeine's get method with loader function for automatic cache population
        List<WhitedRuleConfigPO> configs = getConfigsWithRetry(tenantId);

        log.debug("Retrieved whited configs for tenant: {}, count: {}", tenantId, configs.size());
        return new ArrayList<>(configs); // Return defensive copy
    }

    /**
     * Get configurations with exponential backoff retry mechanism
     * Retries up to 3 times with exponential backoff to handle concurrent access issues
     *
     * @param tenantId the tenant ID to query configurations for
     * @return List of WhitedRuleConfigPO objects, never null
     */
    private List<WhitedRuleConfigPO> getConfigsWithRetry(Long tenantId) {
        final int maxRetries = 3;
        final long baseDelayMs = 1000; // Base delay of 1000ms

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                List<WhitedRuleConfigPO> configs = tenantConfigCache.get(tenantId, this::queryTenantConfigs);
                if (configs != null && !configs.isEmpty()) {
                    for (WhitedRuleConfigPO whitedRuleConfigPO : configs) {
                        if (WhitedRuleTypeEnum.REGO.name().equals(whitedRuleConfigPO.getRuleType())) {
                            String regoContent = whitedRuleConfigPO.getRegoContent();
                            String regoPath = opaRepository.findWhitedConfigPackage(regoContent, whitedRuleConfigPO.getId().toString());
                            String newRegoPolicy = regoContent.replaceFirst("(?<=package )\\S+", regoPath);
                            opaRepository.createOrUpdatePolicy(regoPath, newRegoPolicy);
                        }
                    }
                    return configs;
                }

                log.warn("Retrieved null configs for tenant: {} on attempt {}/{}", tenantId, attempt, maxRetries);

                // If this is not the last attempt, wait with exponential backoff
                if (attempt < maxRetries) {
                    long delayMs = baseDelayMs * (1L << (attempt - 1)); // Exponential backoff: 100ms, 200ms, 400ms
                    log.info("Retrying after {}ms for tenant: {}", delayMs, tenantId);

                    try {
                        TimeUnit.MILLISECONDS.sleep(delayMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        log.warn("Retry interrupted for tenant: {}", tenantId);
                        break;
                    }
                }
            } catch (Exception e) {
                log.error("Error retrieving configs for tenant: {} on attempt {}/{}", tenantId, attempt, maxRetries, e);

                // If this is the last attempt, throw the exception
                if (attempt == maxRetries) {
                    throw e;
                }

                // Wait with exponential backoff before retrying
                long delayMs = baseDelayMs * (1L << (attempt - 1));
                try {
                    TimeUnit.MILLISECONDS.sleep(delayMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    log.warn("Retry interrupted for tenant: {}", tenantId);
                    break;
                }
            }
        }

        log.error("Failed to retrieve configs for tenant: {} after {} attempts, returning empty list", tenantId, maxRetries);
        return new ArrayList<>();
    }


    /**
     * Query whited configurations from database for a specific tenant
     *
     * @param tenantId the tenant ID to query configurations for
     * @return List of WhitedRuleConfigPO objects from database
     */
    private List<WhitedRuleConfigPO> queryTenantConfigs(Long tenantId) {
        List<WhitedRuleConfigPO> allConfigs = new ArrayList<>();

        // Only query enabled configurations
        QueryWhitedRuleDTO queryDto = QueryWhitedRuleDTO.builder()
                .enable(1)
                .build();

        // Set tenant ID list using reflection method call (temporary workaround for Lombok issue)
        try {
            Long globalTenantId = tenantRepository.findGlobalTenant().getId();
            queryDto.setTenantIdList(Stream.of(globalTenantId, tenantId).distinct().toList());
        } catch (Exception e) {
            log.error("Failed to retrieve global tenant or set tenant ID list for tenant: {}", tenantId, e);
            throw new IllegalStateException("Unable to configure tenant isolation for query. Tenant ID: " + tenantId, e);
        }

        // Use pagination to handle large datasets
        queryDto.setSize(configProperties.getQueryPageSize());
        int page = 1;

        while (true) {
            queryDto.setPage(page);
            queryDto.setOffset();

            List<WhitedRuleConfigPO> pageData = whitedRuleConfigMapper.list(queryDto);
            if (CollectionUtils.isEmpty(pageData)) {
                break;
            }

            allConfigs.addAll(pageData);
            page++;

            // Prevent infinite loops by limiting max pages
            if (page > configProperties.getMaxQueryPages()) {
                log.warn("Reached maximum query pages limit ({}) for tenant: {}, stopping pagination",
                        configProperties.getMaxQueryPages(), tenantId);
                break;
            }
        }

        return allConfigs;
    }

    /**
     * Clear cache for a specific tenant
     * This method should be called when tenant configurations are updated
     *
     * @param tenantId the tenant ID to clear cache for
     */
    public void clearTenantCache(Long tenantId) {
        if (tenantId == null) {
            return;
        }

        tenantConfigCache.invalidate(tenantId);
        log.info("Cleared cache for tenant: {}", tenantId);
    }

    /**
     * Clear all cached configurations
     * This method should be called when global configuration changes occur
     */
    public void clearAllCache() {
        tenantConfigCache.invalidateAll();
        log.info("Cleared all whited config cache");
    }

    /**
     * Get cache statistics for monitoring purposes
     * Uses Caffeine's built-in statistics functionality
     *
     * @return Map containing cache statistics
     */
    public Map<String, Object> getCacheStats() {
        CacheStats stats = tenantConfigCache.stats();
        Map<String, Object> result = new HashMap<>();
        result.put("cacheSize", tenantConfigCache.estimatedSize());
        result.put("maxCacheSize", configProperties.getMaxCacheSize());
        result.put("cacheExpirationTimeMs", configProperties.getCacheExpirationTimeMs());
        result.put("hitCount", stats.hitCount());
        result.put("missCount", stats.missCount());
        result.put("hitRate", stats.hitRate());
        result.put("evictionCount", stats.evictionCount());
        result.put("loadCount", stats.loadCount());
        result.put("averageLoadPenalty", stats.averageLoadPenalty());

        return result;
    }

    /**
     * Get whited rule configurations for a specific tenant
     * This method provides tenant isolation for whitelist configurations
     *
     * @param tenantId the tenant ID to get configurations for
     * @return List of WhitedRuleConfigPO objects for the specified tenant
     */
    public List<WhitedRuleConfigPO> getByTenant(Long tenantId) {
        return this.getWhitedConfigsByTenant(tenantId);
    }

}
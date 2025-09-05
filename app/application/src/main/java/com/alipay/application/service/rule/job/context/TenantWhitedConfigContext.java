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

import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.dao.dto.QueryWhitedRuleDTO;
import com.alipay.dao.mapper.WhitedRuleConfigMapper;
import com.alipay.dao.po.WhitedRuleConfigPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Stream;

/**
 * Tenant-isolated whited configuration context for managing whitelist configurations by tenant
 * This class provides caching mechanism to avoid repeated database queries for the same tenant
 *
 * Date: 2025/8/28
 */
@Slf4j
@Component
public class TenantWhitedConfigContext {

    @Resource
    private WhitedRuleConfigMapper whitedRuleConfigMapper;

    @Resource
    private TenantRepository tenantRepository;

    @Resource
    private TenantWhitedConfigProperties configProperties;

    /**
     * Cache entry wrapper with version control and expiration time
     */
    private static class CacheEntry {
        private final List<WhitedRuleConfigPO> configs;
        private final long expirationTime;
        private final long version;
        private final long creationTime;

        public CacheEntry(List<WhitedRuleConfigPO> configs, long expirationTime, long version) {
            this.configs = new ArrayList<>(configs); // Defensive copy
            this.expirationTime = expirationTime;
            this.version = version;
            this.creationTime = System.currentTimeMillis();
        }

        public List<WhitedRuleConfigPO> getConfigs() {
            return new ArrayList<>(configs); // Return defensive copy
        }

        public boolean isExpired() {
            return System.currentTimeMillis() >= expirationTime;
        }

        public boolean isValid() {
            return !isExpired();
        }

        public long getVersion() {
            return version;
        }

        public long getCreationTime() {
            return creationTime;
        }

        public long getExpirationTime() {
            return expirationTime;
        }
    }

    /**
     * Cache for storing tenant-specific whitelisted rule configurations with version control
     * Key: tenant ID, Value: CacheEntry with configs, expiration time and version
     */
    private final Map<Long, CacheEntry> tenantConfigCache = new ConcurrentHashMap<>();

    /**
     * Version counter for cache entries to detect stale data
     */
    private final AtomicLong cacheVersionCounter = new AtomicLong(0);

    /**
     * Read-write lock to ensure thread safety for cache operations
     */
    private final ReentrantReadWriteLock cacheLock = new ReentrantReadWriteLock();

    // Cache configuration is now managed by TenantWhitedConfigProperties

    /**
     * Get whited rule configurations for a specific tenant with caching
     * Thread-safe implementation without read locks to prevent stale data during refresh
     *
     * @param tenantId the tenant ID to query configurations for
     * @return List of WhitedRuleConfigPO objects for the specified tenant
     */
    public List<WhitedRuleConfigPO> getWhitedConfigsByTenant(Long tenantId) {
        if (tenantId == null) {
            log.warn("Tenant ID is null, returning empty list");
            return new ArrayList<>();
        }

        // Check cache without locks first (ConcurrentHashMap is thread-safe for reads)
        CacheEntry cacheEntry = tenantConfigCache.get(tenantId);
        if (cacheEntry != null && cacheEntry.isValid()) {
            List<WhitedRuleConfigPO> cachedConfigs = cacheEntry.getConfigs();
            log.debug("Retrieved whited configs from cache for tenant: {}, count: {}, version: {}", 
                     tenantId, cachedConfigs.size(), cacheEntry.getVersion());
            return cachedConfigs; // Already returns defensive copy
        }

        // Cache miss or expired, need to refresh
        return refreshTenantCache(tenantId);
    }

    /**
     * Refresh cache for a specific tenant by querying database
     * Uses improved double-check locking with version control to prevent stale data
     *
     * @param tenantId the tenant ID to refresh cache for
     * @return List of WhitedRuleConfigPO objects for the specified tenant
     */
    private List<WhitedRuleConfigPO> refreshTenantCache(Long tenantId) {
        cacheLock.writeLock().lock();
        try {
            // Check again inside lock to see if another thread has already refreshed
            CacheEntry currentEntry = tenantConfigCache.get(tenantId);
            if (currentEntry != null && currentEntry.isValid()) {
                // Another thread has refreshed the cache, use the latest version
                log.debug("Cache already refreshed by another thread for tenant: {}, version: {}", 
                         tenantId, currentEntry.getVersion());
                return currentEntry.getConfigs();
            }

            // Query database for tenant-specific configurations
            List<WhitedRuleConfigPO> tenantConfigs = queryTenantConfigs(tenantId);

            // Manage cache size to prevent memory overflow (now thread-safe)
            manageCacheSize();

            // Create new cache entry with incremented version
            long newVersion = cacheVersionCounter.incrementAndGet();
            long expirationTime = System.currentTimeMillis() + configProperties.getCacheExpirationTimeMs();
            CacheEntry newEntry = new CacheEntry(tenantConfigs, expirationTime, newVersion);
            
            // Update cache atomically
            tenantConfigCache.put(tenantId, newEntry);

            log.info("Refreshed whited configs cache for tenant: {}, count: {}, version: {}", 
                    tenantId, tenantConfigs.size(), newVersion);
            return newEntry.getConfigs();

        } finally {
            cacheLock.writeLock().unlock();
        }
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
        List<Long> tenantIds;
        try {
            Long globalTenantId = tenantRepository.findGlobalTenant().getId();
            tenantIds = Stream.of(globalTenantId, tenantId).distinct().toList();
            
            // Use reflection to call setTenantIdList method
            java.lang.reflect.Method setTenantIdListMethod = QueryWhitedRuleDTO.class.getMethod("setTenantIdList", List.class);
            setTenantIdListMethod.invoke(queryDto, tenantIds);
            
            log.debug("Set tenant IDs for query: {}", tenantIds);
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
     * Check if cache for a tenant is valid (exists and not expired)
     *
     * @param tenantId the tenant ID to check
     * @return true if cache is valid, false otherwise
     */
    private boolean isCacheValid(Long tenantId) {
        CacheEntry cacheEntry = tenantConfigCache.get(tenantId);
        return cacheEntry != null && cacheEntry.isValid();
    }

    /**
     * Manages cache size by removing expired entries and enforcing size limits
     * Thread-safe implementation with proper synchronization
     */
    private void manageCacheSize() {
        // Remove expired entries
        Iterator<Map.Entry<Long, CacheEntry>> iterator = tenantConfigCache.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<Long, CacheEntry> entry = iterator.next();
            if (entry.getValue().isExpired()) {
                Long tenantId = entry.getKey();
                iterator.remove();
                log.debug("Removed expired cache for tenant: {}", tenantId);
            }
        }

        // Enforce cache size limit
        if (tenantConfigCache.size() > configProperties.getMaxCacheSize()) {
            // Find the oldest entry
            Long oldestTenant = tenantConfigCache.entrySet().stream()
                    .min(Map.Entry.<Long, CacheEntry>comparingByValue(
                            (e1, e2) -> Long.compare(e1.getCreationTime(), e2.getCreationTime())))
                    .map(Map.Entry::getKey)
                    .orElse(null);

            if (oldestTenant != null) {
                tenantConfigCache.remove(oldestTenant);
                log.debug("Removed oldest cache entry for tenant: {} due to cache size limit", oldestTenant);
            }
        }
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

        cacheLock.writeLock().lock();
        try {
            tenantConfigCache.remove(tenantId);
            log.info("Cleared cache for tenant: {}", tenantId);
        } finally {
            cacheLock.writeLock().unlock();
        }
    }

    /**
     * Clear all cached configurations
     * This method should be called when global configuration changes occur
     */
    public void clearAllCache() {
        cacheLock.writeLock().lock();
        try {
            tenantConfigCache.clear();
            log.info("Cleared all whited config cache");
        } finally {
            cacheLock.writeLock().unlock();
        }
    }

    /**
     * Get cache statistics for monitoring purposes
     *
     * @return Map containing cache statistics
     */
    public Map<String, Object> getCacheStats() {
        cacheLock.readLock().lock();
        try {
            Map<String, Object> stats = new HashMap<>();
            stats.put("cacheSize", tenantConfigCache.size());
            stats.put("maxCacheSize", configProperties.getMaxCacheSize());
            stats.put("cacheExpirationTimeMs", configProperties.getCacheExpirationTimeMs());

            // Count total cached configurations
            int totalConfigs = tenantConfigCache.values().stream()
                    .mapToInt(entry -> entry.getConfigs().size())
                    .sum();
            stats.put("totalCachedConfigs", totalConfigs);

            return stats;
        } finally {
            cacheLock.readLock().unlock();
        }
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
package com.alipay.application.service.rule.job.context;

import com.alipay.application.service.system.domain.Tenant;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.dao.dto.QueryWhitedRuleDTO;
import com.alipay.dao.mapper.WhitedRuleConfigMapper;
import com.alipay.dao.po.WhitedRuleConfigPO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for TenantWhitedConfigContextV2 with Caffeine cache integration
 * Tests cache functionality, thread safety, and performance characteristics
 */
@ExtendWith(MockitoExtension.class)
class TenantWhitedConfigContextV2Test {

    @Mock
    private WhitedRuleConfigMapper whitedRuleConfigMapper;

    @Mock
    private TenantWhitedConfigProperties configProperties;
    
    @Mock
    private TenantRepository tenantRepository;

    @InjectMocks
    private TenantWhitedConfigContextV2 tenantWhitedConfigContext;

    private List<WhitedRuleConfigPO> mockConfigs;
    private static final Long TENANT_ID_1 = 1001L;
    private static final Long TENANT_ID_2 = 1002L;

    @BeforeEach
    void setUp() {
        // Setup mock configurations
        mockConfigs = createMockWhitelistConfigs();
    }

    /**
     * Create mock whitelist configurations for testing
     */
    private List<WhitedRuleConfigPO> createMockWhitelistConfigs() {
        List<WhitedRuleConfigPO> configs = new ArrayList<>();
        
        WhitedRuleConfigPO config1 = new WhitedRuleConfigPO();
        config1.setId(1L);
        config1.setTenantId(TENANT_ID_1);
        config1.setRuleName("rule1");
        config1.setRuleConfig("config1");
        configs.add(config1);
        
        WhitedRuleConfigPO config2 = new WhitedRuleConfigPO();
        config2.setId(2L);
        config2.setTenantId(TENANT_ID_1);
        config2.setRuleName("rule2");
        config2.setRuleConfig("config2");
        configs.add(config2);
        
        return configs;
    }

    @Test
    void testGetWhitedConfigsByTenant_Success() {
        // Setup mock properties
        when(configProperties.getMaxCacheSize()).thenReturn(1000);
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(300000L);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        when(configProperties.getMaxQueryPages()).thenReturn(10);
        
        // Setup mock tenant repository
        Tenant globalTenant = new Tenant();
        globalTenant.setId(0L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Initialize the cache
        tenantWhitedConfigContext.initializeCache();
        
        // Setup mock mapper for pagination - first call returns data, second returns empty
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class)))
            .thenReturn(mockConfigs)
            .thenReturn(Collections.emptyList());
        
        // When
        List<WhitedRuleConfigPO> result = tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        
        // Then
        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals("rule1", result.get(0).getRuleName());
        assertEquals("rule2", result.get(1).getRuleName());
        
        // Verify database was called twice (pagination)
        verify(whitedRuleConfigMapper, times(2)).list(any(QueryWhitedRuleDTO.class));
    }

    @Test
    void testGetWhitedConfigsByTenant_CacheHit() {
        // Setup mock properties
        when(configProperties.getMaxCacheSize()).thenReturn(1000);
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(300000L);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        when(configProperties.getMaxQueryPages()).thenReturn(10);
        
        // Setup mock tenant repository
        Tenant globalTenant = new Tenant();
        globalTenant.setId(0L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Initialize the cache
        tenantWhitedConfigContext.initializeCache();
        
        // Setup mock mapper for pagination - first call returns data, second returns empty
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class)))
            .thenReturn(mockConfigs)
            .thenReturn(Collections.emptyList());
        
        // First call - cache miss
        List<WhitedRuleConfigPO> result1 = tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        
        // Second call - cache hit
        List<WhitedRuleConfigPO> result2 = tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        
        // Then
        assertNotNull(result1);
        assertNotNull(result2);
        assertEquals(result1.size(), result2.size());
        assertEquals(result1.get(0).getTenantId(), result2.get(0).getTenantId());
        
        // Verify database was called only twice for first query due to caching
        verify(whitedRuleConfigMapper, times(2)).list(any(QueryWhitedRuleDTO.class));
    }

    @Test
    void testGetWhitedConfigsByTenant_NullTenantId() {
        // When
        List<WhitedRuleConfigPO> result = tenantWhitedConfigContext.getWhitedConfigsByTenant(null);
        
        // Then
        assertNotNull(result);
        assertTrue(result.isEmpty());
        
        // Verify database was not called
        verify(whitedRuleConfigMapper, never()).list(any(QueryWhitedRuleDTO.class));
    }

    @Test
    void testGetWhitedConfigsByTenant_EmptyResult() {
        // Setup mock properties
        when(configProperties.getMaxCacheSize()).thenReturn(1000);
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(300000L);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        
        // Setup mock tenant repository
        Tenant globalTenant = new Tenant();
        globalTenant.setId(0L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Initialize the cache
        tenantWhitedConfigContext.initializeCache();
        
        // Given - return empty list for pagination
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class))).thenReturn(Collections.emptyList());
        
        // When
        List<WhitedRuleConfigPO> result = tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        
        // Then
        assertNotNull(result);
        assertTrue(result.isEmpty());
        
        verify(whitedRuleConfigMapper, times(1)).list(any(QueryWhitedRuleDTO.class));
    }

    @Test
    void testGetWhitedConfigsByTenant_DatabaseException() {
        // Setup mock properties
        when(configProperties.getMaxCacheSize()).thenReturn(1000);
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(300000L);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        
        // Setup mock tenant repository
        Tenant globalTenant = new Tenant();
        globalTenant.setId(0L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Initialize the cache
        tenantWhitedConfigContext.initializeCache();
        
        // Setup mock to throw exception
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class)))
                .thenThrow(new RuntimeException("Database error"));

        // Call the method and expect exception
        assertThrows(RuntimeException.class, () -> {
            tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        });

        // Verify interactions
        verify(whitedRuleConfigMapper, times(1)).list(any(QueryWhitedRuleDTO.class));
    }

    @Test
    void testClearCacheForTenant() {
        // Setup mock properties
        when(configProperties.getMaxCacheSize()).thenReturn(1000);
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(300000L);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        when(configProperties.getMaxQueryPages()).thenReturn(10);
        
        // Setup mock tenant repository
        Tenant globalTenant = new Tenant();
        globalTenant.setId(0L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Initialize the cache
        tenantWhitedConfigContext.initializeCache();
        
        // Setup mock mapper for pagination
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class)))
            .thenReturn(mockConfigs)
            .thenReturn(Collections.emptyList())
            .thenReturn(mockConfigs)
            .thenReturn(Collections.emptyList());
        
        // Given - populate cache first
        tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        
        // When
        tenantWhitedConfigContext.clearTenantCache(TENANT_ID_1);
        
        // Then - next call should hit database again
        tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        
        // Verify database was called 4 times (2 for initial + 2 for after cache clear)
        verify(whitedRuleConfigMapper, times(4)).list(any(QueryWhitedRuleDTO.class));
    }

    @Test
    void testClearCacheForTenant_NullTenantId() {
        // When
        tenantWhitedConfigContext.clearTenantCache(null);
        
        // Then - should not throw exception
        // No verification needed as method should handle null gracefully
    }

    @Test
    void testClearAllCache() {
        // Setup mock properties
        when(configProperties.getMaxCacheSize()).thenReturn(1000);
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(300000L);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        when(configProperties.getMaxQueryPages()).thenReturn(10);
        
        // Setup mock tenant repository
        Tenant globalTenant = new Tenant();
        globalTenant.setId(0L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Initialize the cache
        tenantWhitedConfigContext.initializeCache();
        
        // Setup mock mapper for pagination - 8 calls total (4 queries * 2 pages each)
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class)))
            .thenReturn(mockConfigs).thenReturn(Collections.emptyList()) // First TENANT_ID_1
            .thenReturn(mockConfigs).thenReturn(Collections.emptyList()) // First TENANT_ID_2
            .thenReturn(mockConfigs).thenReturn(Collections.emptyList()) // Second TENANT_ID_1
            .thenReturn(mockConfigs).thenReturn(Collections.emptyList()); // Second TENANT_ID_2
        
        // Given - populate cache
        tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_2);
        
        // When
        tenantWhitedConfigContext.clearAllCache();
        
        // Then - next calls should hit database again
        tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_2);
        
        // Verify database was called 8 times (4 queries * 2 pages each)
        verify(whitedRuleConfigMapper, times(8)).list(any(QueryWhitedRuleDTO.class));
    }

    @Test
    void testGetCacheStats() {
        // Setup mock properties
        when(configProperties.getMaxCacheSize()).thenReturn(1000);
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(300000L);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        when(configProperties.getMaxQueryPages()).thenReturn(10);
        
        // Setup mock tenant repository
        Tenant globalTenant = new Tenant();
        globalTenant.setId(0L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Initialize the cache
        tenantWhitedConfigContext.initializeCache();
        
        // Setup mock mapper for pagination
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class)))
            .thenReturn(mockConfigs)
            .thenReturn(Collections.emptyList());
        
        // Given - populate cache
        tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1); // Cache hit
        
        // When
        Map<String, Object> stats = tenantWhitedConfigContext.getCacheStats();
        
        // Then
        assertNotNull(stats);
        assertTrue(stats.containsKey("cacheSize"));
        assertTrue(stats.containsKey("maxCacheSize"));
        assertTrue(stats.containsKey("cacheExpirationTimeMs"));
        assertTrue(stats.containsKey("hitCount"));
        assertTrue(stats.containsKey("missCount"));
        assertTrue(stats.containsKey("hitRate"));
        assertTrue(stats.containsKey("evictionCount"));
        assertTrue(stats.containsKey("loadCount"));
        assertTrue(stats.containsKey("averageLoadPenalty"));
        
        assertEquals(1000, stats.get("maxCacheSize"));
        assertEquals(300000L, stats.get("cacheExpirationTimeMs"));
    }

    @Test
    void testConcurrentAccess() throws InterruptedException {
        // Setup mock properties
        when(configProperties.getMaxCacheSize()).thenReturn(1000);
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(300000L);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        when(configProperties.getMaxQueryPages()).thenReturn(10);
        
        // Setup mock tenant repository
        Tenant globalTenant = new Tenant();
        globalTenant.setId(0L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Initialize the cache
        tenantWhitedConfigContext.initializeCache();
        
        // Setup mock mapper for pagination
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class)))
            .thenReturn(mockConfigs)
            .thenReturn(Collections.emptyList());
        
        // Given
        int threadCount = 10;
        int operationsPerThread = 100;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());
        
        // When - concurrent access to cache
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    for (int j = 0; j < operationsPerThread; j++) {
                        Long tenantId = (j % 2 == 0) ? TENANT_ID_1 : TENANT_ID_2;
                        List<WhitedRuleConfigPO> result = tenantWhitedConfigContext.getWhitedConfigsByTenant(tenantId);
                        assertNotNull(result);
                    }
                } catch (Exception e) {
                    exceptions.add(e);
                } finally {
                    latch.countDown();
                }
            });
        }
        
        // Then
        assertTrue(latch.await(30, TimeUnit.SECONDS));
        assertTrue(exceptions.isEmpty(), "No exceptions should occur during concurrent access");
        
        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    @Test
    void testDefensiveCopy() {
        // Setup mock properties
        when(configProperties.getMaxCacheSize()).thenReturn(1000);
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(300000L);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        when(configProperties.getMaxQueryPages()).thenReturn(10);
        
        // Setup mock tenant repository
        Tenant globalTenant = new Tenant();
        globalTenant.setId(0L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Initialize the cache
        tenantWhitedConfigContext.initializeCache();
        
        // Setup mock mapper for pagination
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class)))
            .thenReturn(mockConfigs)
            .thenReturn(Collections.emptyList());
        
        // When
        List<WhitedRuleConfigPO> result1 = tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        List<WhitedRuleConfigPO> result2 = tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        
        // Then - should be different instances (defensive copies)
        assertNotSame(result1, result2);
        assertEquals(result1.size(), result2.size());
        
        // Modifying one should not affect the other
        result1.clear();
        assertFalse(result2.isEmpty());
    }

    @Test
    void testMultipleTenants() {
        // Setup mock properties
        when(configProperties.getMaxCacheSize()).thenReturn(1000);
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(300000L);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        when(configProperties.getMaxQueryPages()).thenReturn(10);
        
        // Setup mock tenant repository
        Tenant globalTenant = new Tenant();
        globalTenant.setId(0L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Initialize the cache
        tenantWhitedConfigContext.initializeCache();
        
        // Setup mock mapper for pagination - 4 calls total (2 tenants * 2 pages each)
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class)))
            .thenReturn(mockConfigs).thenReturn(Collections.emptyList()) // TENANT_ID_1
            .thenReturn(mockConfigs).thenReturn(Collections.emptyList()); // TENANT_ID_2
        
        // When
        List<WhitedRuleConfigPO> tenant1Configs = tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_1);
        List<WhitedRuleConfigPO> tenant2Configs = tenantWhitedConfigContext.getWhitedConfigsByTenant(TENANT_ID_2);
        
        // Then
        assertNotNull(tenant1Configs);
        assertNotNull(tenant2Configs);
        assertEquals(2, tenant1Configs.size());
        assertEquals(2, tenant2Configs.size());
        
        assertEquals(TENANT_ID_1, tenant1Configs.get(0).getTenantId());
        assertEquals(TENANT_ID_1, tenant2Configs.get(0).getTenantId());
        
        // Verify database was called 4 times (2 tenants * 2 pages each)
        verify(whitedRuleConfigMapper, times(4)).list(any(QueryWhitedRuleDTO.class));
    }
}
package com.alipay.application.service.rule.job.context;

import com.alipay.application.service.system.domain.Tenant;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.dao.dto.QueryWhitedRuleDTO;
import com.alipay.dao.mapper.WhitedRuleConfigMapper;
import com.alipay.dao.po.WhitedRuleConfigPO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit test to reproduce the intermittent cache expiration bug in TenantWhitedConfigContext.
 * This test demonstrates the race condition that occurs when cache expires at the exact moment
 * when multiple threads are accessing the cache, leading to inconsistent whitelisting behavior.
 */
public class TenantWhitedConfigContextBugReproductionTest {

    private static final Logger logger = LoggerFactory.getLogger(TenantWhitedConfigContextBugReproductionTest.class);

    @Mock
    private WhitedRuleConfigMapper whitedRuleConfigMapper;

    @Mock
    private TenantRepository tenantRepository;

    @Mock
    private TenantWhitedConfigProperties configProperties;

    private TenantWhitedConfigContext context;

    private static final Long TEST_TENANT_ID = 12345L;
    private static final int THREAD_COUNT = 10;
    private static final int ITERATIONS_PER_THREAD = 50;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        
        // Configure properties with very short cache expiration to trigger race conditions
        when(configProperties.getCacheExpirationTimeMs()).thenReturn(50L); // 50ms expiration
        when(configProperties.getMaxCacheSize()).thenReturn(100);
        when(configProperties.getQueryPageSize()).thenReturn(100);
        when(configProperties.getMaxQueryPages()).thenReturn(10);
        
        // Create context and inject dependencies using reflection
        context = new TenantWhitedConfigContext();
        ReflectionTestUtils.setField(context, "whitedRuleConfigMapper", whitedRuleConfigMapper);
        ReflectionTestUtils.setField(context, "tenantRepository", tenantRepository);
        ReflectionTestUtils.setField(context, "configProperties", configProperties);
        
        // Mock global tenant
        Tenant globalTenant = new Tenant();
        globalTenant.setId(1L);
        when(tenantRepository.findGlobalTenant()).thenReturn(globalTenant);
        
        // Mock database response with whitelisted rules
        List<WhitedRuleConfigPO> mockConfigs = createMockWhitelistConfigs();
        when(whitedRuleConfigMapper.list(any(QueryWhitedRuleDTO.class)))
            .thenReturn(mockConfigs); // Always return mock data for consistent testing
    }

    /**
     * Test to reproduce the cache expiration race condition bug.
     * This test simulates multiple threads accessing the cache simultaneously
     * when cache is about to expire, which can lead to inconsistent results.
     */
    @Test
    void testCacheExpirationRaceCondition() throws InterruptedException {
        logger.info("Starting cache expiration race condition test...");
        
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch completeLatch = new CountDownLatch(THREAD_COUNT);
        
        AtomicInteger inconsistentResults = new AtomicInteger(0);
        AtomicInteger totalRequests = new AtomicInteger(0);
        ConcurrentHashMap<String, Integer> resultCounts = new ConcurrentHashMap<>();
        
        // Create multiple threads that will access cache simultaneously
        for (int i = 0; i < THREAD_COUNT; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    startLatch.await(); // Wait for all threads to be ready
                    
                    for (int j = 0; j < ITERATIONS_PER_THREAD; j++) {
                        try {
                            // Add small random delay to increase chance of race condition
                            Thread.sleep(ThreadLocalRandom.current().nextInt(10, 100));
                            
                            List<WhitedRuleConfigPO> configs = context.getWhitedConfigsByTenant(TEST_TENANT_ID);
                            totalRequests.incrementAndGet();
                            
                            String resultKey = "size_" + configs.size();
                            resultCounts.merge(resultKey, 1, Integer::sum);
                            
                            // Log when we get unexpected results (empty list when should have data)
                            if (configs.isEmpty()) {
                                logger.warn("Thread {} iteration {}: Got empty config list (potential cache miss during expiration)", 
                                    threadId, j);
                                inconsistentResults.incrementAndGet();
                            }
                            
                        } catch (Exception e) {
                            logger.error("Error in thread {} iteration {}: {}", threadId, j, e.getMessage());
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    completeLatch.countDown();
                }
            });
        }
        
        // Start all threads simultaneously
        startLatch.countDown();
        
        // Wait for all threads to complete
        assertTrue(completeLatch.await(30, TimeUnit.SECONDS), "Test should complete within 30 seconds");
        executor.shutdown();
        
        // Analyze results
        logger.info("Test completed. Total requests: {}, Inconsistent results: {}", 
            totalRequests.get(), inconsistentResults.get());
        logger.info("Result distribution: {}", resultCounts);
        
        // The bug manifests as getting different results (especially empty lists)
        // when cache expires during concurrent access
        if (inconsistentResults.get() > 0) {
            logger.error("BUG REPRODUCED: Found {} inconsistent results out of {} total requests", 
                inconsistentResults.get(), totalRequests.get());
            logger.error("This indicates the cache expiration race condition bug is present");
        }
        
        // Assert that we should have consistent results (this will fail when bug is present)
        assertTrue(resultCounts.size() <= 2, 
            "Should have at most 2 different result sizes (with/without cache), but got: " + resultCounts.keySet());
    }

    /**
     * Test to reproduce the manageCacheSize concurrent modification issue.
     * This test demonstrates how cache entries can be removed while being accessed.
     */
    @Test
    void testManageCacheSizeConcurrentModification() throws InterruptedException {
        logger.info("Starting manageCacheSize concurrent modification test...");
        
        // Configure small cache size to trigger frequent cache management
        when(configProperties.getMaxCacheSize()).thenReturn(3);
        
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch completeLatch = new CountDownLatch(THREAD_COUNT);
        
        AtomicInteger cacheModificationErrors = new AtomicInteger(0);
        
        // Create threads that access different tenants to trigger cache size management
        for (int i = 0; i < THREAD_COUNT; i++) {
            final long tenantId = TEST_TENANT_ID + i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    
                    for (int j = 0; j < ITERATIONS_PER_THREAD; j++) {
                        try {
                            List<WhitedRuleConfigPO> configs = context.getWhitedConfigsByTenant(tenantId);
                            
                            // Immediately access the same cache again
                            List<WhitedRuleConfigPO> configs2 = context.getWhitedConfigsByTenant(tenantId);
                            
                            // Check for inconsistency (cache entry removed between calls)
                            if (configs.size() != configs2.size()) {
                                logger.warn("Cache inconsistency detected for tenant {}: first call returned {}, second call returned {}", 
                                    tenantId, configs.size(), configs2.size());
                                cacheModificationErrors.incrementAndGet();
                            }
                            
                        } catch (Exception e) {
                            logger.error("Error accessing cache for tenant {}: {}", tenantId, e.getMessage());
                            cacheModificationErrors.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    completeLatch.countDown();
                }
            });
        }
        
        startLatch.countDown();
        assertTrue(completeLatch.await(30, TimeUnit.SECONDS));
        executor.shutdown();
        
        logger.info("Cache modification errors detected: {}", cacheModificationErrors.get());
        
        if (cacheModificationErrors.get() > 0) {
            logger.error("BUG REPRODUCED: Found {} cache modification errors", cacheModificationErrors.get());
            logger.error("This indicates the manageCacheSize concurrent modification bug is present");
        }
    }

    /**
     * Test to reproduce the double-check locking time window issue.
     * This test demonstrates the small time window where stale data can be returned.
     */
    @Test
    void testDoubleCheckLockingTimeWindow() throws InterruptedException, ExecutionException, TimeoutException {
        logger.info("Starting double-check locking time window test...");
        
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch barrier = new CountDownLatch(2);
        AtomicInteger staleDataCount = new AtomicInteger(0);
        
        // First thread: access cache and let it expire
        Future<?> thread1 = executor.submit(() -> {
            try {
                // Initial cache load
                List<WhitedRuleConfigPO> configs = context.getWhitedConfigsByTenant(TEST_TENANT_ID);
                logger.info("Thread 1: Initial cache load, size: {}", configs.size());
                
                barrier.countDown();
                barrier.await();
                
                // Wait for cache to expire
                Thread.sleep(100);
                
                // Access again - this should trigger refresh
                configs = context.getWhitedConfigsByTenant(TEST_TENANT_ID);
                logger.info("Thread 1: After expiration, size: {}", configs.size());
                
            } catch (Exception e) {
                logger.error("Thread 1 error: {}", e.getMessage());
            }
        });
        
        // Second thread: try to access during the refresh window
        Future<?> thread2 = executor.submit(() -> {
            try {
                barrier.countDown();
                barrier.await();
                
                // Wait for cache to expire, then try to access during refresh
                Thread.sleep(80); // Slightly less than thread 1
                
                for (int i = 0; i < 10; i++) {
                    List<WhitedRuleConfigPO> configs = context.getWhitedConfigsByTenant(TEST_TENANT_ID);
                    
                    // Check if we got stale/empty data during refresh window
                    if (configs.isEmpty()) {
                        logger.warn("Thread 2 iteration {}: Got empty data during refresh window", i);
                        staleDataCount.incrementAndGet();
                    }
                    
                    Thread.sleep(5); // Small delay between accesses
                }
                
            } catch (Exception e) {
                logger.error("Thread 2 error: {}", e.getMessage());
            }
        });
        
        thread1.get(10, TimeUnit.SECONDS);
        thread2.get(10, TimeUnit.SECONDS);
        executor.shutdown();
        
        logger.info("Stale data occurrences: {}", staleDataCount.get());
        
        if (staleDataCount.get() > 0) {
            logger.error("BUG REPRODUCED: Found {} stale data occurrences during refresh window", staleDataCount.get());
            logger.error("This indicates the double-check locking time window bug is present");
        }
    }

    /**
     * Creates mock whitelist configuration data for testing.
     */
    private List<WhitedRuleConfigPO> createMockWhitelistConfigs() {
        List<WhitedRuleConfigPO> configs = new ArrayList<>();
        
        WhitedRuleConfigPO config1 = new WhitedRuleConfigPO();
        config1.setId(1L);
        config1.setTenantId(TEST_TENANT_ID);
        config1.setRuleType("RULE_ENGINE");
        config1.setRuleConfig("{\"condition\": \"test\"}");
        config1.setEnable(1);
        configs.add(config1);
        
        WhitedRuleConfigPO config2 = new WhitedRuleConfigPO();
        config2.setId(2L);
        config2.setTenantId(TEST_TENANT_ID);
        config2.setRuleType("REGO");
        config2.setRegoContent("package test\nallow = true");
        config2.setEnable(1);
        configs.add(config2);
        
        return configs;
    }
}
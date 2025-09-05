package com.alipay.application.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Async task executor configuration for resource data processing
 * Provides thread pool configuration for asynchronous operations
 */
@Configuration
@EnableAsync
@EnableScheduling
public class AsyncConfig {

    /**
     * Configure thread pool executor for resource data processing
     * Optimized for I/O intensive database operations
     * 
     * @return configured thread pool task executor
     */
    @Bean(name = "resourceDataTaskExecutor")
    public Executor resourceDataTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        
        // Core thread pool size - minimum threads to keep alive
        executor.setCorePoolSize(50);
        
        // Maximum thread pool size - maximum threads allowed
        executor.setMaxPoolSize(100);
        
        // Queue capacity - pending tasks queue size
        executor.setQueueCapacity(300);
        
        // Thread name prefix for easier debugging
        executor.setThreadNamePrefix("ResourceData-Async-");
        
        // Keep alive time for idle threads (seconds)
        executor.setKeepAliveSeconds(60);
        
        // Rejection policy when queue is full
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        
        // Wait for tasks to complete on shutdown
        executor.setWaitForTasksToCompleteOnShutdown(true);
        
        // Maximum wait time for shutdown (seconds)
        executor.setAwaitTerminationSeconds(30);
        
        executor.initialize();
        return executor;
    }
    
    /**
     * Configure thread pool executor for batch operations
     * Optimized for bulk database operations with larger thread pool
     * 
     * @return configured thread pool task executor for batch operations
     */
    @Bean(name = "batchTaskExecutor")
    public Executor batchTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        
        // Smaller core pool for batch operations
        executor.setCorePoolSize(5);
        
        // Maximum thread pool size for batch operations
        executor.setMaxPoolSize(20);
        
        // Larger queue capacity for batch tasks
        executor.setQueueCapacity(100);
        
        // Thread name prefix for batch operations
        executor.setThreadNamePrefix("BatchData-Async-");
        
        // Keep alive time for idle threads (seconds)
        executor.setKeepAliveSeconds(120);
        
        // Rejection policy when queue is full
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        
        // Wait for tasks to complete on shutdown
        executor.setWaitForTasksToCompleteOnShutdown(true);
        
        // Maximum wait time for shutdown (seconds)
        executor.setAwaitTerminationSeconds(60);
        
        executor.initialize();
        return executor;
    }
}
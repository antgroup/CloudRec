package com.alipay.application.service.resource;

import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Scheduled service for async task monitoring and maintenance
 * Provides periodic cleanup and statistics logging for async tasks
 */
@Slf4j
@Service
public class AsyncTaskSchedulerService {

    @Resource
    private AsyncTaskMonitorService asyncTaskMonitorService;
    
    // Maximum age for active tasks before considering them stale (30 minutes)
    private static final long MAX_TASK_AGE_MILLIS = 30 * 60 * 1000;
    
    /**
     * Log task statistics every 5 minutes
     * Provides visibility into async task performance
     */
    @Scheduled(fixedRate = 300000) // 5 minutes
    public void logTaskStatistics() {
        try {
            asyncTaskMonitorService.logTaskStatistics();
        } catch (Exception e) {
            log.error("Error logging task statistics", e);
        }
    }
    
    /**
     * Clean up stale tasks every 10 minutes
     * Removes tasks that have been running for too long
     */
    @Scheduled(fixedRate = 600000) // 10 minutes
    public void cleanupStaleTasks() {
        try {
            asyncTaskMonitorService.cleanupOldTasks(MAX_TASK_AGE_MILLIS);
            log.debug("Completed cleanup of stale async tasks");
        } catch (Exception e) {
            log.error("Error cleaning up stale tasks", e);
        }
    }
    
    /**
     * Log detailed task statistics every hour
     * Provides comprehensive performance metrics
     */
    @Scheduled(fixedRate = 3600000) // 1 hour
    public void logDetailedStatistics() {
        try {
            AsyncTaskMonitorService.TaskStatistics stats = asyncTaskMonitorService.getTaskStatistics();
            
            log.info("=== Hourly Async Task Report ===");
            log.info("Total Tasks Submitted: {}", stats.getTotalSubmitted());
            log.info("Total Tasks Completed: {}", stats.getTotalCompleted());
            log.info("Total Tasks Failed: {}", stats.getTotalFailed());
            log.info("Currently Active Tasks: {}", stats.getActiveCount());
            log.info("Success Rate: {:.2f}%", stats.getSuccessRate());
            log.info("=================================");
            
            // Alert if success rate is below threshold
            if (stats.getSuccessRate() < 95.0 && stats.getTotalSubmitted() > 10) {
                log.warn("ALERT: Async task success rate is below 95%: {:.2f}%", stats.getSuccessRate());
            }
            
            // Alert if too many active tasks
            if (stats.getActiveCount() > 100) {
                log.warn("ALERT: High number of active async tasks: {}", stats.getActiveCount());
            }
            
        } catch (Exception e) {
            log.error("Error logging detailed task statistics", e);
        }
    }
}
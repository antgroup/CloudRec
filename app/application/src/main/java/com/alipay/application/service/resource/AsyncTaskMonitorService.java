package com.alipay.application.service.resource;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Service for monitoring async task execution status and performance metrics
 * Provides tracking capabilities for resource data processing tasks
 */
@Slf4j
@Service
public class AsyncTaskMonitorService {

    // Task execution counters
    private final AtomicLong totalTasksSubmitted = new AtomicLong(0);
    private final AtomicLong totalTasksCompleted = new AtomicLong(0);
    private final AtomicLong totalTasksFailed = new AtomicLong(0);
    
    // Active tasks tracking
    private final ConcurrentHashMap<String, TaskInfo> activeTasks = new ConcurrentHashMap<>();
    
    /**
     * Record task submission for monitoring
     * 
     * @param taskId unique task identifier
     * @param cloudAccountId cloud account ID
     * @param resourceType resource type
     * @param platform platform name
     */
    public void recordTaskSubmission(String taskId, String cloudAccountId, String resourceType, String platform) {
        totalTasksSubmitted.incrementAndGet();
        TaskInfo taskInfo = new TaskInfo(taskId, cloudAccountId, resourceType, platform, System.currentTimeMillis());
        activeTasks.put(taskId, taskInfo);
        
        log.debug("Task submitted for monitoring: {}, cloudAccountId: {}, resourceType: {}, platform: {}", 
                taskId, cloudAccountId, resourceType, platform);
    }
    
    /**
     * Record task completion for monitoring
     * 
     * @param taskId unique task identifier
     */
    public void recordTaskCompletion(String taskId) {
        totalTasksCompleted.incrementAndGet();
        TaskInfo taskInfo = activeTasks.remove(taskId);
        
        if (taskInfo != null) {
            long executionTime = System.currentTimeMillis() - taskInfo.getStartTime();
            log.info("Task completed: {}, cloudAccountId: {}, resourceType: {}, platform: {}, executionTime: {}ms", 
                    taskId, taskInfo.getCloudAccountId(), taskInfo.getResourceType(), 
                    taskInfo.getPlatform(), executionTime);
        }
    }
    
    /**
     * Record task failure for monitoring
     * 
     * @param taskId unique task identifier
     * @param error the exception that caused the failure
     */
    public void recordTaskFailure(String taskId, Throwable error) {
        totalTasksFailed.incrementAndGet();
        TaskInfo taskInfo = activeTasks.remove(taskId);
        
        if (taskInfo != null) {
            long executionTime = System.currentTimeMillis() - taskInfo.getStartTime();
            log.error("Task failed: {}, cloudAccountId: {}, resourceType: {}, platform: {}, executionTime: {}ms, error: {}", 
                    taskId, taskInfo.getCloudAccountId(), taskInfo.getResourceType(), 
                    taskInfo.getPlatform(), executionTime, error.getMessage());
        }
    }
    
    /**
     * Get current task execution statistics
     * 
     * @return TaskStatistics object containing current metrics
     */
    public TaskStatistics getTaskStatistics() {
        return new TaskStatistics(
                totalTasksSubmitted.get(),
                totalTasksCompleted.get(),
                totalTasksFailed.get(),
                activeTasks.size()
        );
    }
    
    /**
     * Log current task statistics periodically
     * This method can be called by a scheduled task
     */
    @Async("resourceDataTaskExecutor")
    public CompletableFuture<Void> logTaskStatistics() {
        TaskStatistics stats = getTaskStatistics();
        log.info("Task Statistics - Submitted: {}, Completed: {}, Failed: {}, Active: {}",
                stats.getTotalSubmitted(), stats.getTotalCompleted(),
                stats.getTotalFailed(), stats.getActiveCount());
        return CompletableFuture.completedFuture(null);
    }
    
    /**
     * Clean up old completed tasks from memory
     * Remove tasks that have been running for more than specified time
     * 
     * @param maxAgeMillis maximum age in milliseconds
     */
    public void cleanupOldTasks(long maxAgeMillis) {
        long currentTime = System.currentTimeMillis();
        activeTasks.entrySet().removeIf(entry -> {
            boolean shouldRemove = (currentTime - entry.getValue().getStartTime()) > maxAgeMillis;
            if (shouldRemove) {
                log.warn("Removing stale task: {}, cloudAccountId: {}, age: {}ms", 
                        entry.getKey(), entry.getValue().getCloudAccountId(), 
                        currentTime - entry.getValue().getStartTime());
            }
            return shouldRemove;
        });
    }
    
    /**
     * Inner class to hold task information
     */
    private static class TaskInfo {
        private final String taskId;
        private final String cloudAccountId;
        private final String resourceType;
        private final String platform;
        private final long startTime;
        
        public TaskInfo(String taskId, String cloudAccountId, String resourceType, String platform, long startTime) {
            this.taskId = taskId;
            this.cloudAccountId = cloudAccountId;
            this.resourceType = resourceType;
            this.platform = platform;
            this.startTime = startTime;
        }
        
        public String getTaskId() { return taskId; }
        public String getCloudAccountId() { return cloudAccountId; }
        public String getResourceType() { return resourceType; }
        public String getPlatform() { return platform; }
        public long getStartTime() { return startTime; }
    }
    
    /**
     * Inner class to hold task statistics
     */
    public static class TaskStatistics {
        private final long totalSubmitted;
        private final long totalCompleted;
        private final long totalFailed;
        private final int activeCount;
        
        public TaskStatistics(long totalSubmitted, long totalCompleted, long totalFailed, int activeCount) {
            this.totalSubmitted = totalSubmitted;
            this.totalCompleted = totalCompleted;
            this.totalFailed = totalFailed;
            this.activeCount = activeCount;
        }
        
        public long getTotalSubmitted() { return totalSubmitted; }
        public long getTotalCompleted() { return totalCompleted; }
        public long getTotalFailed() { return totalFailed; }
        public int getActiveCount() { return activeCount; }
        
        public double getSuccessRate() {
            long totalProcessed = totalCompleted + totalFailed;
            return totalProcessed > 0 ? (double) totalCompleted / totalProcessed * 100.0 : 0.0;
        }
    }
}
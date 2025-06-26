package com.alipay.application.service.collector;


import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/*
 *@title SchedulerManager
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/17 12:39
 */
@Slf4j
public class SchedulerManager {
    private static final ScheduledExecutorService SCHEDULER;

    static {
        int corePoolSize = Runtime.getRuntime().availableProcessors() * 2;
        SCHEDULER = new ScheduledThreadPoolExecutor(
                corePoolSize,
                new CustomThreadFactory("thread-scheduler-"),
                new ThreadPoolExecutor.DiscardPolicy()
        );

        ((ScheduledThreadPoolExecutor) SCHEDULER).setKeepAliveTime(30, TimeUnit.SECONDS);
        ((ScheduledThreadPoolExecutor) SCHEDULER).allowCoreThreadTimeOut(true);
    }

    public static ScheduledExecutorService getScheduler() {
        return SCHEDULER;
    }

    public static void shutdown() {
        SCHEDULER.shutdown();
        try {
            if (!SCHEDULER.awaitTermination(15, TimeUnit.SECONDS)) {
                List<Runnable> droppedTasks = SCHEDULER.shutdownNow();
                log.error("Uncaught exception in {} tasks", droppedTasks.size());
            }
        } catch (InterruptedException e) {
            SCHEDULER.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    static class CustomThreadFactory implements ThreadFactory {
        private final String namePrefix;
        private final AtomicInteger threadNumber = new AtomicInteger(1);

        CustomThreadFactory(String namePrefix) {
            this.namePrefix = namePrefix;
        }

        @Override
        public Thread newThread(@NotNull Runnable r) {
            Thread t = new Thread(r, namePrefix + threadNumber.getAndIncrement());
            t.setUncaughtExceptionHandler((thread, ex) -> {
                log.error("Uncaught exception in {}: {}", thread.getName(), ex.getMessage(), ex);
            });
            t.setDaemon(false);
            return t;
        }
    }
}

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
package com.alipay.api.config.filter.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Rate limiting service using sliding window algorithm
 * Provides memory-based rate limiting functionality
 * 
 * @author jietian
 * @version 1.0
 * @since 2024
 */
@Service
@Slf4j
public class RateLimitService {
    
    /**
     * Storage for rate limiting windows
     * Key: rate limit key (IP, user ID, etc.)
     * Value: sliding window data
     */
    private final ConcurrentHashMap<String, SlidingWindow> rateLimitMap = new ConcurrentHashMap<>();
    
    /**
     * Read-write lock for thread safety during cleanup operations
     */
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    
    /**
     * Check if the request is allowed based on rate limiting rules
     * 
     * @param key rate limiting key
     * @param maxRequests maximum requests allowed in time window
     * @param timeWindowSeconds time window in seconds
     * @return true if request is allowed, false if rate limit exceeded
     */
    public boolean isAllowed(String key, int maxRequests, int timeWindowSeconds) {
        lock.readLock().lock();
        try {
            long currentTime = System.currentTimeMillis();
            long windowSizeMs = timeWindowSeconds * 1000L;
            
            SlidingWindow window = rateLimitMap.computeIfAbsent(key, k -> new SlidingWindow());
            
            synchronized (window) {
                // Clean expired time slots
                window.cleanExpiredSlots(currentTime, windowSizeMs);
                
                // Check if current request count exceeds limit
                if (window.getCurrentCount() >= maxRequests) {
                    log.warn("Rate limit exceeded for key: {}, current count: {}, max allowed: {}", 
                            key, window.getCurrentCount(), maxRequests);
                    return false;
                }
                
                // Add current request
                window.addRequest(currentTime);
                
                log.debug("Request allowed for key: {}, current count: {}/{}", 
                        key, window.getCurrentCount(), maxRequests);
                return true;
            }
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Clean up expired rate limiting data
     * Should be called periodically to prevent memory leaks
     */
    public void cleanup() {
        lock.writeLock().lock();
        try {
            long currentTime = System.currentTimeMillis();
            long expireTime = 5 * 60 * 1000L; // 5 minutes
            
            rateLimitMap.entrySet().removeIf(entry -> {
                SlidingWindow window = entry.getValue();
                synchronized (window) {
                    return window.isExpired(currentTime, expireTime);
                }
            });
            
            log.debug("Rate limit cleanup completed, remaining entries: {}", rateLimitMap.size());
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Get current statistics for monitoring
     * 
     * @param key rate limiting key
     * @return current request count, -1 if key not found
     */
    public int getCurrentCount(String key) {
        lock.readLock().lock();
        try {
            SlidingWindow window = rateLimitMap.get(key);
            if (window == null) {
                return 0;
            }
            synchronized (window) {
                return window.getCurrentCount();
            }
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Sliding window implementation for rate limiting
     */
    private static class SlidingWindow {
        /**
         * Storage for request timestamps
         * Key: time slot (timestamp / 1000)
         * Value: request count in that second
         */
        private final ConcurrentHashMap<Long, AtomicLong> timeSlots = new ConcurrentHashMap<>();
        
        /**
         * Last access time for cleanup purposes
         */
        private volatile long lastAccessTime = System.currentTimeMillis();
        
        /**
         * Add a request to the current time slot
         * 
         * @param timestamp current timestamp
         */
        public void addRequest(long timestamp) {
            long timeSlot = timestamp / 1000; // Group by seconds
            timeSlots.computeIfAbsent(timeSlot, k -> new AtomicLong(0)).incrementAndGet();
            lastAccessTime = timestamp;
        }
        
        /**
         * Clean expired time slots
         * 
         * @param currentTime current timestamp
         * @param windowSizeMs window size in milliseconds
         */
        public void cleanExpiredSlots(long currentTime, long windowSizeMs) {
            long expireTime = (currentTime - windowSizeMs) / 1000;
            timeSlots.entrySet().removeIf(entry -> entry.getKey() <= expireTime);
        }
        
        /**
         * Get current request count in the window
         * 
         * @return total request count
         */
        public int getCurrentCount() {
            return timeSlots.values().stream()
                    .mapToInt(AtomicLong::intValue)
                    .sum();
        }
        
        /**
         * Check if this window has expired
         * 
         * @param currentTime current timestamp
         * @param expireTime expire time in milliseconds
         * @return true if expired
         */
        public boolean isExpired(long currentTime, long expireTime) {
            return (currentTime - lastAccessTime) > expireTime;
        }
    }
}
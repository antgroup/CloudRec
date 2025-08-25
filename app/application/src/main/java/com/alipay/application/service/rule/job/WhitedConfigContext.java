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
package com.alipay.application.service.rule.job;


import com.alipay.application.service.rule.domain.repo.OpaRepository;
import com.alipay.common.enums.WhitedRuleTypeEnum;
import com.alipay.dao.dto.QueryWhitedRuleDTO;
import com.alipay.dao.mapper.WhitedRuleConfigMapper;
import com.alipay.dao.po.WhitedRuleConfigPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Date: 2025/3/31
 * Author: lz
 */
@Slf4j
@Component
public class WhitedConfigContext {

    @Resource
    private WhitedRuleConfigMapper whitedRuleConfigMapper;

    @Resource
    private OpaRepository opaRepository;

    private static final ThreadLocal<List<WhitedRuleConfigPO>> WHITED_CONFIG_THREAD_LOCAL_CACHE = new ThreadLocal<>();
    
    /**
     * Read-write lock to ensure thread safety for cache operations
     */
    private final ReentrantReadWriteLock cacheLock = new ReentrantReadWriteLock();

    /**
     * Load enabled whited configurations and update OPA policies
     * This method fetches enabled REGO rules and updates the OPA repository
     */
    private void loadEnableWhitedConfigs() {
        QueryWhitedRuleDTO dto = QueryWhitedRuleDTO.builder().build();
        dto.setEnable(1);
        dto.setSize(1000);
        dto.setRuleType(WhitedRuleTypeEnum.REGO.name());
        List<WhitedRuleConfigPO> list = whitedRuleConfigMapper.list(dto);
        for (WhitedRuleConfigPO whitedRuleConfigPO : list) {
            String regoContent = whitedRuleConfigPO.getRegoContent();
            String regoPath = opaRepository.findWhitedConfigPackage(regoContent, whitedRuleConfigPO.getId().toString());
            String newRegoPolicy = regoContent.replaceFirst("(?<=package )\\S+", regoPath);
            opaRepository.createOrUpdatePolicy(regoPath, newRegoPolicy);
        }
    }

    /**
     * Refresh whited configurations with thread safety
     * This method loads enabled configs and initializes cache with write lock protection
     * 
     * @throws RuntimeException if any error occurs during refresh process
     */
    public void refreshWhitedConfigs() {
        cacheLock.writeLock().lock();
        try {
            loadEnableWhitedConfigs();
            initWhitedConfigCache();
        } catch (Exception e) {
            log.error("refreshWhitedConfigs error", e);
            throw new RuntimeException("refreshWhitedConfigs error", e);
        } finally {
            cacheLock.writeLock().unlock();
        }
    }

    /**
     * Initialize whited configuration cache using pagination
     * This method loads all enabled configurations into ThreadLocal cache
     * Note: This method should be called within write lock protection
     */
    private void initWhitedConfigCache() {
        List<WhitedRuleConfigPO> whitedRuleConfigPOList = new ArrayList<>();
        QueryWhitedRuleDTO queryWhitedRuleDTO = QueryWhitedRuleDTO.builder().build();
        queryWhitedRuleDTO.setEnable(1);

        int count = whitedRuleConfigMapper.count(queryWhitedRuleDTO);
        if (count == 0) {
            WHITED_CONFIG_THREAD_LOCAL_CACHE.set(new ArrayList<>());
            return;
        }
        List<WhitedRuleConfigPO> whitedRuleConfigPOS = WHITED_CONFIG_THREAD_LOCAL_CACHE.get();
        if (CollectionUtils.isEmpty(whitedRuleConfigPOS) || whitedRuleConfigPOS.size() != count) {
            WHITED_CONFIG_THREAD_LOCAL_CACHE.remove();
        }

        queryWhitedRuleDTO.setSize(100);
        int page = 1;
        while (true) {
            queryWhitedRuleDTO.setPage(page);
            queryWhitedRuleDTO.setOffset();
            List<WhitedRuleConfigPO> dataList = whitedRuleConfigMapper.list(queryWhitedRuleDTO);
            if (CollectionUtils.isEmpty(dataList)) {
                break;
            }
            whitedRuleConfigPOList.addAll(dataList);
            page++;
        }
        WHITED_CONFIG_THREAD_LOCAL_CACHE.set(whitedRuleConfigPOList);
    }

    /**
     * Clear ThreadLocal cache for current thread
     * This method should be called to prevent memory leaks
     */
    protected void clear() {
        cacheLock.writeLock().lock();
        try {
            WHITED_CONFIG_THREAD_LOCAL_CACHE.remove();
        } finally {
            cacheLock.writeLock().unlock();
        }
    }

    /**
     * Get whited rule configurations from cache with lazy loading
     * If cache is empty, it will trigger a refresh operation
     * 
     * @return List of WhitedRuleConfigPO objects from cache
     */
    protected List<WhitedRuleConfigPO> get() {
        cacheLock.readLock().lock();
        try {
            List<WhitedRuleConfigPO> whitedRuleConfigPOS = WHITED_CONFIG_THREAD_LOCAL_CACHE.get();
            if (CollectionUtils.isEmpty(whitedRuleConfigPOS)) {
                // Release read lock before acquiring write lock to avoid deadlock
                cacheLock.readLock().unlock();
                refreshWhitedConfigs();
                cacheLock.readLock().lock();
            }
            return WHITED_CONFIG_THREAD_LOCAL_CACHE.get();
        } finally {
            cacheLock.readLock().unlock();
        }
    }

}

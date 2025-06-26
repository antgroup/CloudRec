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
package com.alipay.application.service.system.job;


import com.alipay.application.service.rule.exposed.GroupJoinService;
import com.alipay.application.service.rule.exposed.InitRuleService;
import com.alipay.application.service.system.domain.Tenant;
import com.alipay.application.service.system.domain.User;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.application.service.system.domain.repo.UserRepository;
import com.alipay.application.service.system.utils.SecretKeyUtil;
import com.alipay.common.constant.TenantConstants;
import com.alipay.common.enums.PlatformType;
import com.alipay.common.enums.ResourceGroupType;
import com.alipay.common.exception.BizException;
import com.alipay.dao.mapper.PlatformMapper;
import com.alipay.dao.mapper.ResourceMapper;
import com.alipay.dao.po.PlatformPO;
import com.alipay.dao.po.ResourcePO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.Objects;

/*
 *@title Init
 *@description Initialization task, used to initialize the necessary information of the system
 *@version 1.0
 *@create 2024/12/16 13:07
 */
@Slf4j
@Component
public class SystemInitializer {

    @Resource
    private PlatformMapper platformMapper;

    @Resource
    private ResourceMapper resourceMapper;

    @Resource
    private UserRepository userRepository;

    @Resource
    private TenantRepository tenantRepository;

    @Resource
    private GroupJoinService groupJoinService;

    @Resource
    private InitRuleService initRuleService;

    @Resource
    private SecretKeyUtil secretKeyUtil;

    @Value("${cloudrec.rule.path}")
    private String rulePath;


    @EventListener
    private void init(ApplicationReadyEvent event) {
        try {
            // Initialize platform information
            initPlatformType();

            // Initialize some resource type fields to test rego rules
            initSomeExampleResourceType();

            // Initialize default tenants and global tenants
            initDefaultTenant();

            // Initialize the default user
            initDefaultUser();

            // Initialize the default rule group
            groupJoinService.initDefaultGroup();

            // Initialize the key to encrypt the account authentication information
            secretKeyUtil.initKey();

            // Initialize rule types
            initRuleService.initRuleType();

            // Initialize rule
//            if (StringUtils.isNotBlank(rulePath)) {
//                log.info("find rule path: {}, will init system default rules", rulePath);
//                initRuleService.loadRuleFromLocalFile();
//            }
        } catch (Exception e) {
            log.error("init system error", e);
        }
    }

    private void initDefaultTenant() {
        Tenant defaultTenant = tenantRepository.find(TenantConstants.DEFAULT_TENANT);
        if (defaultTenant == null) {
            defaultTenant = Tenant.createDefaultTenant();
            tenantRepository.save(defaultTenant);
        }

        Tenant globalTenant = tenantRepository.find(TenantConstants.GLOBAL_TENANT);
        if (globalTenant == null) {
            globalTenant = Tenant.createGlobalTenant();
            tenantRepository.save(globalTenant);
        }
    }

    /**
     * init default user
     */
    private void initDefaultUser() {
        User user = userRepository.find(User.DEFAULT_USER_ID);
        if (user == null) {
            User defaultUser = User.createDefaultUser();
            userRepository.save(defaultUser);
        }

        user = userRepository.find(User.DEFAULT_USER_ID);
        if (user == null) {
            throw new BizException("default user not found");
        }

        // join default tenant
        Tenant defaultTenant = tenantRepository.find(TenantConstants.DEFAULT_TENANT);
        if (defaultTenant != null) {
            tenantRepository.join(user.getId(), defaultTenant.getId());
        }

        // join global tenant
        Tenant globalTenant = tenantRepository.find(TenantConstants.GLOBAL_TENANT);
        if (globalTenant != null) {
            tenantRepository.join(user.getId(), globalTenant.getId());
        }

    }

    /**
     * init platform type
     */
    private void initPlatformType() {
        for (PlatformType value : PlatformType.values()) {
            if (Objects.equals(value, PlatformType.UNKNOWN)) {
                continue;
            }
            int count = platformMapper.findOne(value.getPlatform());
            PlatformPO platformPO = new PlatformPO();
            platformPO.setPlatform(value.getPlatform());
            platformPO.setPlatformName(value.getCnName());
            if (count == 0) {
                platformMapper.insertSelective(platformPO);
            } else {
                platformMapper.updateByPrimaryKeySelective(platformPO);
            }
        }
    }

    private static final String EXAMPLE_RESOURCE_TYPE = "ECS";

    /**
     * init some resource type
     * As a test only，resourceType will be automatically initialized after the collector is turned on
     */
    private void initSomeExampleResourceType() {
        ResourcePO resourcePO = resourceMapper.findOne(PlatformType.ALI_CLOUD.getPlatform(), EXAMPLE_RESOURCE_TYPE);
        if (resourcePO == null) {
            resourcePO = new ResourcePO();
            resourcePO.setPlatform(PlatformType.ALI_CLOUD.getPlatform());
            resourcePO.setResourceType(EXAMPLE_RESOURCE_TYPE);
            resourcePO.setResourceName(EXAMPLE_RESOURCE_TYPE);
            resourcePO.setResourceGroupType(ResourceGroupType.COMPUTE.getCode());
            resourceMapper.insertSelective(resourcePO);
        }

    }
}

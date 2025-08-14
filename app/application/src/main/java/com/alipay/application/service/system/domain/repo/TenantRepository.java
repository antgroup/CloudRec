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
package com.alipay.application.service.system.domain.repo;


import com.alipay.application.service.system.domain.Tenant;

import java.util.List;

/*
 *@title TenantRepository
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/1/17 16:03
 */
public interface TenantRepository {

    Tenant find(Long id);

    List<Tenant> findAll(String status);

    List<Tenant> findList(String userId);

    void save(Tenant tenant);

    Tenant find(String name);

    int exist(String userId, Long tenantId);

    int memberCount(Long id);

    void join(Long uid, Long tenantId);

    void remove(Long uid, Long tenantId);

    boolean isSelected(Long tenantId, String ruleCode);

    boolean isDefaultRule(String ruleCode);

    Tenant findGlobalTenant();

    void removeSelectedRule(Long tenantId, String ruleCode);

    List<String> findSelectTenantList(String ruleCode);

    boolean isTenantAdmin(String userId, Long tenantId);

    void changeUserTenantRole(String roleName, Long tenantId, String userId);
}

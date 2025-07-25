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
import com.alipay.application.service.system.domain.enums.RoleNameType;
import com.alipay.common.constant.TenantConstants;
import com.alipay.dao.dto.TenantDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/*
 *@title TenantRepositoryImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/1/17 17:46
 */
@Slf4j
@Repository
public class TenantRepositoryImpl implements TenantRepository {

    @Resource
    private TenantMapper tenantMapper;

    @Resource
    private TenantUserMapper tenantUserMapper;

    @Resource
    private UserMapper userMapper;

    @Resource
    private TenantConverter tenantConverter;

    @Resource
    private TenantRuleMapper tenantRuleMapper;

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private RuleMapper ruleMapper;

    @Override
    public Tenant find(Long id) {
        TenantPO tenantPO = tenantMapper.selectByPrimaryKey(id);
        return tenantConverter.toEntity(tenantPO);
    }


    @Override
    public List<Tenant> findAll(String status) {
        TenantDTO tenantDTO = new TenantDTO();
        tenantDTO.setStatus(status);
        List<TenantPO> list = tenantMapper.findList(tenantDTO);
        return list.stream().map(tenantConverter::toEntity).collect(Collectors.toList());
    }

    @Override
    public List<Tenant> findList(String userId) {
        List<TenantPO> tenantPOS = tenantMapper.findListByUserId(userId);
        return tenantPOS.stream().map(tenantConverter::toEntity).collect(Collectors.toList());
    }

    @Override
    public void save(Tenant tenant) {
        TenantPO tenantPO = tenantMapper.selectByPrimaryKey(tenant.getId());
        if (tenantPO == null) {
            tenantMapper.insertSelective(tenantConverter.toPo(tenant));
        } else {
            tenantMapper.updateByPrimaryKeySelective(tenantConverter.toPo(tenant));
        }
    }

    @Override
    public Tenant find(String name) {
        TenantPO tenantPO = tenantMapper.findByTenantName(name);
        return tenantConverter.toEntity(tenantPO);
    }


    @Override
    public int exist(String userId, Long tenantId) {
        UserPO userPO = userMapper.findOne(userId);
        if (userPO == null) {
            return 0;
        }
        return tenantMapper.findRecord(userPO.getId(), tenantId);
    }

    @Override
    public int memberCount(Long id) {
        return tenantMapper.findMemberCountByTenantId(id);
    }

    @Override
    public void join(Long uid, Long tenantId) {
        TenantUserPO tenantUserPO = tenantUserMapper.findOne(uid, tenantId);
        if (tenantUserPO == null) {
            tenantUserPO = new TenantUserPO();
            tenantUserPO.setUserId(uid);
            tenantUserPO.setTenantId(tenantId);
            // The default role is normal user
            tenantUserPO.setRoleName(RoleNameType.user.name());
            tenantUserMapper.insertSelective(tenantUserPO);
        }
    }

    @Override
    public void remove(Long uid, Long tenantId) {
        UserPO userPO = userMapper.selectByPrimaryKey(uid);
        if (userPO == null) {
            return;
        }
        tenantUserMapper.del(userPO.getId(), tenantId);
    }

    @Override
    public boolean isSelected(Long tenantId, String ruleCode) {
        if (tenantId == null || ruleCode == null) {
            return false;
        }
        TenantRulePO tenantRulePO = tenantRuleMapper.findOne(tenantId, ruleCode);
        return tenantRulePO != null;
    }

    @Override
    public boolean isDefaultRule(String ruleCode) {
        try {
            Tenant tenant = this.find(TenantConstants.GLOBAL_TENANT);
            TenantRulePO tenantRulePO = tenantRuleMapper.findOne(tenant.getId(), ruleCode);
            return tenantRulePO != null;
        } catch (Exception e) {
            log.error("isDefaultRule error", e);
            return false;
        }
    }

    @Override
    public Tenant findGlobalTenant() {
        return this.find(TenantConstants.GLOBAL_TENANT);
    }

    @Override
    public void removeSelectedRule(Long tenantId, String ruleCode) {
        TenantPO tenantPO = tenantMapper.selectByPrimaryKey(tenantId);
        if (tenantPO == null) {
            return;
        }

        TenantRulePO tenantRulePO = tenantRuleMapper.findOne(tenantId, ruleCode);
        if (tenantRulePO == null) {
            return;
        }

        RulePO rulePO = ruleMapper.findOne(tenantRulePO.getRuleCode());
        if (rulePO == null) {
            return;
        }

        // Delete tenant select rule
        tenantRuleMapper.deleteByPrimaryKey(tenantRulePO.getId());

        // Delete risk data
        if (isDefaultRule(tenantRulePO.getRuleCode()) && !TenantConstants.GLOBAL_TENANT.equals(tenantPO.getTenantName())) {
            log.info("Non-global tenants cancel self-selection and do not delete data");
            return;
        }

        if (TenantConstants.GLOBAL_TENANT.equals(tenantPO.getTenantName())) {
            // Delete risk data for non-selected rules tenants
            List<TenantRulePO> selectRuleList = tenantRuleMapper.findByCode(ruleCode);
            List<Long> list = selectRuleList.stream().map(TenantRulePO::getId).filter(id -> !id.equals(tenantId)).toList();
            if (CollectionUtils.isEmpty(list)) {
                ruleScanResultMapper.deleteByRuleIdAndTenantId(rulePO.getId(), tenantId);
            }
        } else {
            // Delete the corresponding risk data
            ruleScanResultMapper.deleteByRuleIdAndTenantId(rulePO.getId(), tenantId);
        }
    }

    @Override
    public List<String> findSelectTenantList(String ruleCode) {
        List<String> tenantNameList = new ArrayList<>();
        List<TenantRulePO> selectRulesList = tenantRuleMapper.findByCode(ruleCode);
        for (TenantRulePO tenantRulePO : selectRulesList) {
            TenantPO tenantPO = tenantMapper.selectByPrimaryKey(tenantRulePO.getTenantId());
            if (tenantPO != null) {
                tenantNameList.add(tenantPO.getTenantName());
            }
        }
        return tenantNameList;
    }

    @Override
    public boolean isTenantAdmin(String userId, Long tenantId) {
        UserPO userPO = userMapper.findOne(userId);
        TenantUserPO tenantUserPO = tenantUserMapper.findOne(userPO.getId(), tenantId);
        return tenantUserPO != null && Objects.equals(tenantUserPO.getRoleName(), RoleNameType.admin.name());
    }

    @Override
    public void changeUserTenantRole(String roleName, Long tenantId, String userId) {
        UserPO userPO = userMapper.findOne(userId);
        TenantUserPO tenantUserPO = tenantUserMapper.findOne(userPO.getId(), tenantId);
        if (tenantUserPO == null) {
            return;
        }
        tenantUserPO.setRoleName(roleName);
        tenantUserMapper.updateByPrimaryKeySelective(tenantUserPO);
    }
}

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


import com.alipay.application.service.system.domain.User;
import com.alipay.application.service.system.domain.enums.RoleNameType;
import com.alipay.dao.mapper.TenantUserMapper;
import com.alipay.dao.mapper.UserMapper;
import com.alipay.dao.po.TenantUserPO;
import com.alipay.dao.po.UserPO;
import jakarta.annotation.Resource;
import org.springframework.stereotype.Repository;

/*
 *@title UserRepositoryImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/1/17 13:45
 */
@Repository
public class UserRepositoryImpl implements UserRepository {

    @Resource
    private UserMapper userMapper;

    @Resource
    private TenantUserMapper tenantUserMapper;

    @Resource
    private UserConverter userConverter;

    @Override
    public void del(Long id) {
        userMapper.deleteByPrimaryKey(id);
    }

    @Override
    public void save(User user) {
        UserPO userPO = userMapper.findOne(user.getUserId());
        if (userPO == null) {
            userPO = userConverter.toPo(user);
            userMapper.insertSelective(userPO);
        } else {
            userPO = userConverter.toPo(user);
            userMapper.updateByPrimaryKeySelective(userPO);
        }
    }

    @Override
    public User find(String userId, String password) {
        UserPO login = userMapper.find(userId, password);
        if (login != null) {
            return userConverter.toEntity(login);
        }
        return null;
    }


    @Override
    public User find(String userId) {
        UserPO userPO = userMapper.findOne(userId);
        if (userPO != null) {
            User user = userConverter.toEntity(userPO);
            TenantUserPO tenantUserPO = tenantUserMapper.findOne(user.getId(), user.getTenantId());
            user.setSelectTenantRoleName(tenantUserPO != null ? tenantUserPO.getRoleName() : RoleNameType.user.name());
            return user;
        }
        return null;
    }

    @Override
    public User findByUserName(String userName) {
        UserPO userPO = userMapper.findByUserName(userName);
        if (userPO != null) {
            return userConverter.toEntity(userPO);
        }
        return null;
    }

    @Override
    public void switchTenant(String userId, Long tenantId) {
        UserPO userPO = userMapper.findOne(userId);
        userPO.setTenantId(tenantId);
        userMapper.updateByPrimaryKeySelective(userPO);
    }
}

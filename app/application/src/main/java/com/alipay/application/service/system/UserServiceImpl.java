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
package com.alipay.application.service.system;

import com.alipay.application.service.system.domain.Tenant;
import com.alipay.application.service.system.domain.User;
import com.alipay.application.service.system.domain.enums.RoleNameType;
import com.alipay.application.service.system.domain.enums.Status;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.application.service.system.domain.repo.UserRepository;
import com.alipay.application.service.system.utils.TokenUtil;
import com.alipay.application.share.request.admin.QueryUserListRequest;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.system.UserVO;
import com.alipay.common.exception.BizException;
import com.alipay.common.exception.UserNoLoginException;
import com.alipay.common.exception.UserNotFindException;
import com.alipay.dao.dto.UserDTO;
import com.alipay.dao.mapper.InviteCodeMapper;
import com.alipay.dao.mapper.UserMapper;
import com.alipay.dao.po.InviteCodePO;
import com.alipay.dao.po.UserPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/*
 *@title UserServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/14 11:38
 */
@Slf4j
@Service
public class UserServiceImpl implements UserService {

    @Resource
    private TenantService tenantService;

    @Resource
    private UserRepository userRepository;

    @Resource
    private UserMapper userMapper;

    @Resource
    private TenantRepository tenantRepository;

    @Resource
    private InviteCodeMapper inviteCodeMapper;

    @Override
    public void changeUserStatus(Long id, String status) {
        UserPO userPO = userMapper.selectByPrimaryKey(id);

        userPO.setStatus(status);

        userMapper.updateByPrimaryKeySelective(userPO);
    }

    @Override
    public ListVO<UserVO> queryUserList(QueryUserListRequest request) {

        ListVO<UserVO> listVO = new ListVO<>();

        UserDTO userDTO = new UserDTO();
        userDTO.setUserId(request.getUserId());
        userDTO.setUsername(request.getUsername());
        // Page、Size
        userDTO.setPage(request.getPage());
        userDTO.setSize(request.getSize());
        userDTO.setOffset();

        int count = userMapper.findCount(userDTO);
        if (count == 0) {
            return listVO;
        }

        List<UserPO> list = userMapper.findList(userDTO);

        List<UserVO> collect = list.stream().map(UserVO::toVo).collect(Collectors.toList());
        collect.forEach(t -> {
            List<Tenant> tenantList = tenantRepository.findList(t.getUserId());
            if (!CollectionUtils.isEmpty(tenantList)) {
                List<Long> tenantIds = tenantList.stream().map(Tenant::getId).toList();
                t.setTenantIds(StringUtils.join(tenantIds, ","));
            }
        });

        listVO.setTotal(count);
        listVO.setData(collect);

        return listVO;
    }

    @Override
    public void changeUserRole(Long id, String roleName) {
        User user = new User();

        user.changeRole(id, RoleNameType.getRole(roleName));

        userRepository.save(user);
    }

    @Override
    public UserVO queryUserInfo(String token) {
        User user = TokenUtil.parseToken(token);
        if (Objects.isNull(user) || StringUtils.isEmpty(user.getUserId())) {
            throw new UserNoLoginException("Login expired");
        }

        user = userRepository.find(user.getUserId());
        if (user == null) {
            throw new UserNoLoginException("The account no longer exists, please contact the administrator");
        }

        UserVO userVO = UserVO.toVo(user);
        userVO.setToken(token);

        if (user.getRoleName() != null) {
            Tenant tenant = tenantRepository.find(user.getTenantId());
            if (tenant != null) {
                userVO.setTenantName(tenant.getTenantName());
            }
        }
        // Update last login time
        user.refreshLastLoginTime();
        userRepository.save(user);

        return userVO;
    }

    @Override
    public String login(String userId, String password, String code) {
        User user = userRepository.find(userId, password);
        if (user == null) {
            throw new UserNotFindException("Wrong username or password");
        }

        String sign = TokenUtil.sign(user.getUsername(), user.getUserId(), user.getRoleName().name());
        if (StringUtils.isEmpty(sign)) {
            throw new RuntimeException("System error, please contact the administrator");
        }

        if (user.getTenantId() == null) {
            try {
                tenantService.joinDefaultTenant(userId);
            } catch (Exception e) {
                log.error("Join default tenant failed", e);
            }
        }

        if (Strings.isNotBlank(code)) {
            try {
                InviteCodePO inviteCodePO = inviteCodeMapper.findOne(code);
                tenantService.joinUser(userId, inviteCodePO.getTenantId());
                // switch tenant
                userRepository.switchTenant(userId, inviteCodePO.getTenantId());

                // update invite code
                inviteCodePO.setUserId(userId);
                inviteCodeMapper.updateByPrimaryKeySelective(inviteCodePO);
            } catch (Exception e) {
                log.error("Join invite tenant failed", e);
            }
        }

        return sign;
    }

    @Transactional(rollbackFor = Exception.class)
    @Override
    public void create(String userId, String username, String password, String roleName, String tenantIds) {
        User user = userRepository.find(userId);
        if (user != null) {
            throw new RuntimeException("User already exists");
        }

        user = new User();
        user.setUserId(userId);
        user.setUsername(username);
        user.setStatus(Status.valid);
        user.setPassword(password);
        user.setRoleName(RoleNameType.getRole(roleName));

        userRepository.save(user);

        // auto join default tenant
        List<Tenant> tenants = tenantService.joinUserByTenants(userId, tenantIds);
        // update user select tenant
        if (!CollectionUtils.isEmpty(tenants)) {
            user.setTenantId(tenants.get(0).getId());
            userRepository.save(user);
        }
    }

    @Override
    public void update(String userId, String username, String password, String roleName, String tenantIds) {
        User user = userRepository.find(userId);
        if (user == null) {
            throw new RuntimeException("User does not exist");
        }

        if (StringUtils.isNotBlank(StringUtils.trim(password))) {
            user.setPassword(password);
        }

        user.setUsername(username);
        user.setRoleName(RoleNameType.getRole(roleName));

        // check tenantId
        if (StringUtils.isNotBlank(tenantIds)) {
            List<Tenant> tenants = tenantService.joinUserByTenants(userId, tenantIds);
            if (!CollectionUtils.isEmpty(tenants)) {
                user.setTenantId(tenants.get(0).getId());
            }
        }
        userRepository.save(user);
    }

    @Override
    public void delete(String userId) {
        if (userId.equals(User.DEFAULT_USER_ID)) {
            throw new RuntimeException("The default user cannot be deleted");
        }
        User user = userRepository.find(userId);
        if (user == null) {
            throw new RuntimeException("User does not exist");
        }
        userRepository.del(user.getId());
    }

    @Override
    public void changePassword(String userId, String newPassword, String oldPassword) {
        User user = userRepository.find(userId);
        if (user == null) {
            throw new RuntimeException("User does not exist");
        }

        user = userRepository.find(userId, oldPassword);
        if (user == null) {
            throw new RuntimeException("The old password is incorrect");
        }

        user.setPassword(newPassword);

        userRepository.save(user);
    }

    @Transactional(rollbackFor = RuntimeException.class)
    @Override
    public void register(String userId, String username, String password, String email, String code) {
        InviteCodePO inviteCodePO = inviteCodeMapper.findOne(code);
        if (inviteCodePO == null) {
            throw new BizException("Invite code is invalid");
        }

        if (inviteCodePO.getUserId() != null) {
            throw new BizException("Invite code has been used");
        }

        this.create(userId, username, password, RoleNameType.user.name(), String.valueOf(inviteCodePO.getTenantId()));

        // update invite code inuse
        inviteCodePO.setUserId(userId);
        inviteCodeMapper.updateByPrimaryKeySelective(inviteCodePO);

        // switch tenant
        userRepository.switchTenant(userId, inviteCodePO.getTenantId());
    }

    @Override
    public void joinTenant(String inviteCode, String userId) {
        InviteCodePO inviteCodePO = inviteCodeMapper.findOne(inviteCode);
        if (inviteCodePO == null) {
            throw new BizException("Invite code is invalid");
        }

        if (inviteCodePO.getUserId() != null) {
            throw new BizException("Invite code has been used");
        }

        tenantService.joinUser(userId, inviteCodePO.getTenantId());
    }

}

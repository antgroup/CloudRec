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
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.system.TenantVO;
import com.alipay.application.share.vo.system.UserVO;
import com.alipay.application.share.vo.user.InvitationCodeVO;
import com.alipay.common.constant.TenantConstants;
import com.alipay.common.exception.BizException;
import com.alipay.common.exception.TenantEditException;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.dto.TenantDTO;
import com.alipay.dao.mapper.InviteCodeMapper;
import com.alipay.dao.mapper.TenantMapper;
import com.alipay.dao.po.InviteCodePO;
import com.alipay.dao.po.TenantPO;
import com.alipay.dao.po.UserPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

/*
 *@title TenantServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/13 17:44
 */

@Slf4j
@Service
public class TenantServiceImpl implements TenantService {

    @Resource
    private TenantRepository tenantRepository;

    @Resource
    private TenantMapper tenantMapper;

    @Resource
    private UserRepository userRepository;

    @Resource
    private InviteCodeMapper inviteCodeMapper;

    @Override
    public ListVO<TenantVO> findList(TenantDTO tenantDTO) {
        ListVO<TenantVO> listVO = new ListVO<>();
        int count = tenantMapper.findCount(tenantDTO);
        if (count == 0) {
            return listVO;
        }

        if (tenantDTO.getPageLimit() != null && tenantDTO.getPageLimit()) {
            // 只返回当前用户加入的租户列表
            tenantDTO.setOffset();
            List<TenantPO> list = tenantMapper.findList(tenantDTO);
            List<TenantVO> collect = list.stream().map(TenantVO::toVO).sorted(tenantComparator()).collect(Collectors.toList());
            listVO.setTotal(count);
            listVO.setData(collect);
        } else {
            List<TenantPO> list = tenantMapper.findList(tenantDTO);
            List<TenantVO> collect = list.stream().map(TenantVO::toVO)
                    .filter(item -> !item.getTenantName().equals(TenantConstants.GLOBAL_TENANT))
                    .sorted(tenantComparator())
                    .collect(Collectors.toList());
            listVO.setTotal(count);
            listVO.setData(collect);
        }
        return listVO;
    }

    @Override
    public List<TenantVO> findListV2(String userId) {
        User user = userRepository.find(userId);
        if (user == null) {
            return List.of();
        }

        if (Objects.equals(user.getRoleName(), RoleNameType.admin)) {
            List<TenantPO> list = tenantMapper.findAll();
            return list.stream().map(TenantVO::toVO).sorted(tenantComparator()).toList();
        } else {
            List<TenantPO> list = tenantMapper.findListByUserId(userId);
            if (CollectionUtils.isEmpty(list)) {
                return List.of();
            }

            return list.stream().map(TenantVO::toVO).sorted(tenantComparator()).toList();
        }
    }

    @Override
    public ListVO<TenantVO> findAll() {
        ListVO<TenantVO> listVO = new ListVO<>();
        TenantDTO tenantDTO = new TenantDTO();
        tenantDTO.setPageLimit(Boolean.FALSE);

        int count = tenantMapper.findCount(tenantDTO);
        if (count == 0) {
            return listVO;
        }

        List<TenantPO> list = tenantMapper.findList(tenantDTO);
        List<TenantVO> collect = list.stream().map(TenantVO::toVO)
                .sorted(tenantComparator())
                .collect(Collectors.toList());
        listVO.setTotal(count);
        listVO.setData(collect);
        return listVO;
    }

    @Override
    public void saveTenant(Tenant tenant) {
        if (Objects.equals(tenant.getTenantName(), TenantConstants.DEFAULT_TENANT)) {
            throw new TenantEditException();
        }
        if (Objects.equals(tenant.getTenantName(), TenantConstants.GLOBAL_TENANT)) {
            throw new TenantEditException();
        }

        tenantRepository.save(tenant);
    }

    @Override
    public ListVO<UserVO> queryMemberList(TenantDTO tenantDTO) {
        ListVO<UserVO> listVO = new ListVO<>();

        int count = tenantRepository.memberCount(tenantDTO.getId());
        if (count == 0) {
            return listVO;
        }

        tenantDTO.setOffset();
        List<UserPO> list = tenantMapper.findMemberList(tenantDTO);
        List<UserVO> collect = list.stream().map(UserVO::toVo).toList();
        listVO.setTotal(count);
        listVO.setData(collect);
        return listVO;
    }

    @Override
    public void joinUser(String userId, Long tenantId) {
        User user = userRepository.find(userId);
        if (user == null) {
            throw new BizException("User does not exist:" + userId);
        }

        tenantRepository.join(user.getId(), tenantId);
    }

    @Override
    public ApiResponse<String> removeUser(String userId, Long tenantId) {
        User user = userRepository.find(userId);
        if (user == null) {
            return new ApiResponse<>(ApiResponse.FAIL_CODE, "User does not exist:" + userId);
        }
        tenantRepository.remove(user.getId(), tenantId);
        return ApiResponse.SUCCESS;
    }

    @Override
    public ApiResponse<String> changeTenant(String userId, Long tenantId) {
        User user = userRepository.find(userId);
        if (user == null) {
            return new ApiResponse<>(ApiResponse.FAIL_CODE, "User does not exist:" + userId);
        }

        Tenant tenant = tenantRepository.find(tenantId);
        if (tenant == null) {
            return new ApiResponse<>(ApiResponse.FAIL_CODE, "Tenant does not exist:" + tenantId);
        }

        int count = tenantRepository.exist(userId, tenantId);
        if (count == 0) {
            return new ApiResponse<>(ApiResponse.FAIL_CODE, "The user has not joined the tenant:" + tenantId);
        }

        if (!tenantId.equals(user.getTenantId())) {
            user.setTenantId(tenantId);
            userRepository.save(user);
        }

        return ApiResponse.SUCCESS;
    }

    private static Comparator<TenantVO> tenantComparator() {
        return Comparator.comparingInt(t -> {
            String tenantName = t.getTenantName();
            if (TenantConstants.GLOBAL_TENANT.equals(tenantName)) {
                return 0;
            } else if (TenantConstants.DEFAULT_TENANT.equals(tenantName)) {
                return 1;
            } else {
                return 2;
            }
        });
    }

    @Override
    public ApiResponse<List<TenantVO>> listAddedTenants(String userId) {
        User user = userRepository.find(userId);
        if (user == null) {
            return new ApiResponse<>(ApiResponse.FAIL_CODE, "User does not exist:" + userId);
        }

        List<TenantPO> list = tenantMapper.findListByUserId(userId);
        List<TenantVO> collect = list.stream()
                .map(TenantVO::toVO)
                .sorted(tenantComparator())
                .collect(Collectors.toList());
        return new ApiResponse<>(collect);
    }

    @Override
    public void joinDefaultTenant(String userId) {
        // Determine whether the default tenant exists, and creates it if it does not exist.
        Tenant tenant = tenantRepository.find(TenantConstants.DEFAULT_TENANT);
        if (tenant == null) {
            tenant = new Tenant(null, TenantConstants.DEFAULT_TENANT, Status.valid, TenantConstants.DEFAULT_TENANT_DESC);
            tenantRepository.save(tenant);
        }

        // join default tenant
        joinUser(userId, tenant.getId());

        // select default tenant
        User user = userRepository.find(userId);
        user.setTenantId(tenant.getId());
        userRepository.save(user);
    }

    @Override
    public List<Tenant> joinUserByTenants(String userId, String tenantIds) {

        User user = userRepository.find(userId);
        if (user == null) {
            throw new BizException("User does not exist:" + userId);
        }


        List<Tenant> tenantList = new ArrayList<>();
        //check before tenant&user
        if (StringUtils.isNotBlank(tenantIds)) {
            //check before tenant_user
            List<TenantPO> tenantPOList = tenantMapper.findListByUserId(user.getUserId());
            for (TenantPO tenantPO : tenantPOList) {
                tenantRepository.remove(user.getId(), tenantPO.getId());
            }

            for (String tenantIdStr : StringUtils.split(tenantIds, ",")) {
                Long tenantId = Long.valueOf(tenantIdStr);
                Tenant tenant = tenantRepository.find(tenantId);
                if (Objects.nonNull(tenant)) {
                    tenantRepository.join(user.getId(), tenantId);
                    tenantList.add(tenant);
                }
            }
        }

        //若没有符合的租户，默认设置default租户
        if (CollectionUtils.isEmpty(tenantList)) {
            joinDefaultTenant(userId);
            Tenant tenant = tenantRepository.find(TenantConstants.DEFAULT_TENANT);
            tenantList.add(tenant);
        } else {
            //更新user携带租户
            user.setTenantId(tenantList.get(0).getId());
            userRepository.save(user);
        }
        return tenantList;
    }

    @Override
    public void changeUserTenantRole(String roleName, Long tenantId, String userId) {
        User user = userRepository.find(userId);
        if (user == null) {
            throw new BizException("User does not exist:" + userId);
        }

        Tenant tenant = tenantRepository.find(tenantId);
        if (tenant == null) {
            throw new BizException("Tenant does not exist:" + tenantId);
        }

        int count = tenantRepository.exist(userId, tenantId);
        if (count == 0) {
            throw new BizException("The user has not joined the tenant:" + tenantId);
        }

        // The current user must be an administrator under the tenant to modify the tenant member role
        boolean isTenantAdmin = tenantRepository.isTenantAdmin(UserInfoContext.getCurrentUser().getUserId(), tenantId);
        if (!isTenantAdmin) {
            throw new BizException("The user is not the tenant admin:" + tenantId);
        }

        tenantRepository.changeUserTenantRole(roleName, tenantId, userId);
    }

    @Override
    public String createInviteCode(Long tenantId) {
        String code = UUID.randomUUID().toString();

        InviteCodePO inviteCodePO = new InviteCodePO();
        inviteCodePO.setCode(code);
        inviteCodePO.setTenantId(tenantId);
        inviteCodePO.setInviter(UserInfoContext.getCurrentUser().getUserId());
        inviteCodeMapper.insertSelective(inviteCodePO);

        return code;
    }

    @Override
    public InvitationCodeVO checkInviteCode(String inviteCode) {
        InviteCodePO inviteCodePO = inviteCodeMapper.findOne(inviteCode);
        if (Objects.isNull(inviteCodePO)) {
            throw new BizException("Invite code not found");
        }

        if (Strings.isNotBlank(inviteCodePO.getUserId())) {
            throw new BizException("Invite code has been used");
        }

        InvitationCodeVO vo = InvitationCodeVO.toVO(inviteCodePO);
        TenantPO tenantPO = tenantMapper.selectByPrimaryKey(inviteCodePO.getTenantId());
        if (Objects.isNull(tenantPO)) {
            throw new BizException("Tenant not found");
        }
        vo.setTenantName(tenantPO.getTenantName());

        if (Strings.isNotEmpty(inviteCodePO.getInviter())) {
            User user = userRepository.find(inviteCodePO.getInviter());
            vo.setInviter(user != null ? user.getUsername() : "");
        }
        return vo;
    }
}

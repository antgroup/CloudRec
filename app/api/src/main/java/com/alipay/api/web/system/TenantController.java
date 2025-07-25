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
package com.alipay.api.web.system;

import com.alipay.api.config.filter.annotation.aop.AdminPermissionLimit;
import com.alipay.api.config.filter.annotation.aop.AuthenticateToken;
import com.alipay.api.web.system.request.QueryTenantListRequest;
import com.alipay.application.service.system.TenantService;
import com.alipay.application.service.system.domain.Tenant;
import com.alipay.application.service.system.domain.enums.Status;
import com.alipay.application.share.request.admin.*;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.system.TenantVO;
import com.alipay.application.share.vo.system.UserVO;
import com.alipay.application.share.vo.user.InvitationCodeVO;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.context.UserInfoDTO;
import com.alipay.dao.dto.TenantDTO;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.BeanUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/*
 *@title TenantApi
 *@description Tenant-related interfaces
 *@author jietian
 *@version 1.0
 *@create 2024/6/13 17:41
 */
@RestController
@RequestMapping("/api/tenant")
@Validated
public class TenantController {

    @Resource
    private TenantService tenantService;

    /**
     * Get a list of tenants
     */
    @PostMapping("/queryTenantList")
    public ApiResponse<ListVO<TenantVO>> findList(@Validated @RequestBody QueryTenantListRequest request,
                                                  BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        TenantDTO tenantDTO = new TenantDTO();
        BeanUtils.copyProperties(request, tenantDTO);
        ListVO<TenantVO> listVO = tenantService.findList(tenantDTO);
        return new ApiResponse<>(listVO);
    }

    /**
     * Get a list of tenants
     */
    @AuthenticateToken
    @PostMapping("/queryTenantListV2")
    public ApiResponse<List<TenantVO>> findListV2(HttpServletRequest request) {
        List<TenantVO> list = tenantService.findListV2(UserInfoContext.getCurrentUser().getUserId());
        return new ApiResponse<>(list);
    }

    @GetMapping("/queryAllTenantList")
    public ApiResponse<ListVO<TenantVO>> queryAllTenantList() {
        ListVO<TenantVO> listVO = tenantService.findAll();
        return new ApiResponse<>(listVO);
    }

    /**
     * Save tenant information
     */
    @AdminPermissionLimit
    @PostMapping("/saveTenant")
    public ApiResponse<String> saveTenant(@Validated @RequestBody SaveTenantRequest req,
                                          BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        Tenant tenant = new Tenant(req.getId(), req.getTenantName(), Status.getStatus(req.getStatus()), req.getTenantDesc());

        tenantService.saveTenant(tenant);

        return ApiResponse.SUCCESS;
    }

    /**
     * View members within tenant
     */
    @PostMapping("/queryMember")
    public ApiResponse<ListVO<UserVO>> queryMember(@Validated @RequestBody QueryMemberRequest request,
                                                   BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        TenantDTO tenantDTO = new TenantDTO();
        BeanUtils.copyProperties(request, tenantDTO);

        ListVO<UserVO> listVO = tenantService.queryMemberList(tenantDTO);
        return new ApiResponse<>(listVO);
    }

    /**
     * Add a member
     *
     * @param request request
     */
    @PostMapping("/joinUser")
    public ApiResponse<String> joinUser(@Validated @RequestBody JoinUserRequest request, BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        tenantService.joinUser(request.getUserId(), request.getTenantId());
        return ApiResponse.SUCCESS;
    }

    /**
     * Remove members
     *
     */
    @DeleteMapping("/removeUser")
    public ApiResponse<String> removeUser(@RequestBody @Validated RemoveUserRequest request, BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }
        return tenantService.removeUser(request.getUserId(), request.getTenantId());
    }

    /**
     * Switch the current user's tenant
     */
    @PostMapping("/changeTenant")
    @AuthenticateToken
    public ApiResponse<String> changeTenant(@Validated @RequestBody ChangeTenantRequest changeTenantRequest, BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }
        return tenantService.changeTenant(UserInfoContext.getCurrentUser().getUserId(), changeTenantRequest.getTenantId());
    }


    /**
     * change tenant user role
     */
    @PostMapping("/changeUserTenantRole")
    @AuthenticateToken
    public ApiResponse<String> changeUserTenantRole(@Validated @RequestBody ChangeUserTenantRoleRequest request, BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }
        tenantService.changeUserTenantRole(request.getRoleName(), request.getTenantId(), request.getUserId());
        return ApiResponse.SUCCESS;
    }

    /**
     * Query the list of tenants that the current user has joined
     */
    @GetMapping("/listAddedTenants")
    @AuthenticateToken
    public ApiResponse<List<TenantVO>> listAddedTenants() {
        UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
        return tenantService.listAddedTenants(currentUser.getUserId());
    }

    /**
     * Create an inviteCode
     *
     * @return inviteCode
     */
    @PostMapping("/createInviteCode")
    @AuthenticateToken
    public ApiResponse<String> createInviteCode(@Validated @RequestBody CreateInviteCodeRequest request, BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }
        String inviteCode = tenantService.createInviteCode(request.getCurrentTenantId());
        return new ApiResponse<>(ApiResponse.SUCCESS_CODE, inviteCode, ApiResponse.SUCCESS.getMsg());
    }

    /**
     * check inviteCode
     */
    @PostMapping("/checkInviteCode")
    public ApiResponse<InvitationCodeVO> checkInviteCode(@Validated @RequestBody CheckInviteCodeRequest request, BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }
        return new ApiResponse<>(tenantService.checkInviteCode(request.getInviteCode()));
    }
}

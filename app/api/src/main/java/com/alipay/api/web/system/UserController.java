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
import com.alipay.api.web.system.request.UserLoginRequest;
import com.alipay.application.service.system.UserService;
import com.alipay.application.service.system.domain.enums.RoleNameType;
import com.alipay.application.share.request.admin.*;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.system.UserVO;
import com.alipay.common.enums.Status;
import com.alipay.common.exception.UserNoLoginException;
import com.alipay.dao.context.UserInfoContext;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/*
 *@title UserController
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/14 11:35
 */
@RestController
@RequestMapping("/api/user")
@Validated
@Slf4j
public class UserController {


    @Resource
    private UserService userService;

    @PostMapping("/login")
    public ApiResponse<String> login(@Validated @RequestBody UserLoginRequest request, BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }

        String sign = userService.login(request.getUserId(), request.getPassword(), request.getInviteCode());
        return new ApiResponse<>(sign);
    }

    @AdminPermissionLimit
    @PostMapping("/createUser")
    public ApiResponse<String> createUser(@RequestBody CreateUserRequest request) {
        userService.create(request.getUserId(), request.getUsername(), request.getPassword(), request.getRoleName(), request.getTenantIds());
        return ApiResponse.SUCCESS;
    }

    @PostMapping("/register")
    public ApiResponse<String> register(@RequestBody @Validated RegisterRequest request, BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        userService.register(request.getUserId(), request.getUsername(), request.getPassword(), request.getEmail(), request.getCode());
        return ApiResponse.SUCCESS;
    }

    @AuthenticateToken
    @PostMapping("/joinTenant")
    public ApiResponse<String> joinTenant(@RequestBody @Validated JoinTenantRequest request, BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        userService.joinTenant(request.getInviteCode(), UserInfoContext.getCurrentUser().getUserId());
        return ApiResponse.SUCCESS;
    }

    @AdminPermissionLimit
    @PostMapping("/updateUser")
    public ApiResponse<String> updateUser(@Validated @RequestBody CreateUserRequest request, BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        userService.update(request.getUserId(), request.getUsername(), request.getPassword(), request.getRoleName(), request.getTenantIds());
        return ApiResponse.SUCCESS;
    }

    @AdminPermissionLimit
    @DeleteMapping("/deleteUser")
    public ApiResponse<String> deleteUser(@RequestParam String userId) {
        userService.delete(userId);
        return ApiResponse.SUCCESS;
    }

    @PostMapping("/queryUserInfo")
    public ApiResponse<UserVO> queryUserInfo(HttpServletRequest request)
            throws Exception {
        String token = request.getHeader("token");
        if (StringUtils.isBlank(token) || "null".equals(token)) {
            throw new UserNoLoginException("login exception");
        }
        UserVO userVO = userService.queryUserInfo(token);
        return new ApiResponse<>(userVO);
    }

    /**
     * Enable or disable member accounts within the group
     *
     * @param request request
     */
    @AdminPermissionLimit
    @PostMapping("/changeUserStatus")
    public ApiResponse<String> changeUserStatus(@Validated @RequestBody ChangeUserStatusRequest request,
                                                BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        Status.exist(request.getStatus());
        userService.changeUserStatus(request.getId(), request.getStatus());
        return ApiResponse.SUCCESS;
    }


    @PostMapping("/queryUserList")
    public ApiResponse<ListVO<UserVO>> queryUserList(@Validated @RequestBody QueryUserListRequest request,
                                                     BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        ListVO<UserVO> listVO = userService.queryUserList(request);
        return new ApiResponse<>(listVO);
    }

    @AdminPermissionLimit
    @PostMapping("/changeUserRole")
    public ApiResponse<String> changeUserRole(@Validated @RequestBody ChangeUserRoleRequest request,
                                              BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        boolean exist = RoleNameType.exist(request.getRoleName());
        if (!exist) {
            throw new RuntimeException("roleName must be user OR admin");
        }

        userService.changeUserRole(request.getId(), request.getRoleName());
        return ApiResponse.SUCCESS;
    }

    @PostMapping("/changePassword")
    public ApiResponse<String> changePassword(@Validated @RequestBody ChangePasswordRequest request,
                                              BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        userService.changePassword(request.getUserId(), request.getNewPassword(), request.getOldPassword());
        return ApiResponse.SUCCESS;
    }

}

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
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.system.TenantVO;
import com.alipay.application.share.vo.system.UserVO;
import com.alipay.application.share.vo.user.InvitationCodeVO;
import com.alipay.dao.dto.TenantDTO;

import java.util.List;

/*
 *@title TenantService
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/13 17:44
 */
public interface TenantService {


    ListVO<TenantVO> findList(TenantDTO tenantDTO);

    List<TenantVO> findListV2(String userId);

    ListVO<TenantVO> findAll();


    void saveTenant(Tenant tenant);


    ListVO<UserVO> queryMemberList(TenantDTO tenantDTO);


    void joinUser(String userId, Long tenantId);


    ApiResponse<String> removeUser(String userId, Long tenantId);


    ApiResponse<String> changeTenant(String userId, Long tenantId);


    ApiResponse<List<TenantVO>> listAddedTenants(String userId);


    void joinDefaultTenant(String userId);

    List<Tenant> joinUserByTenants(String userId, String tenantIds);

    void changeUserTenantRole(String roleName, Long tenantId, String userId);

    String createInviteCode(Long tenantId);

    InvitationCodeVO checkInviteCode(String inviteCode);
}

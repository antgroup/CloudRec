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

import com.alipay.application.share.request.admin.QueryUserListRequest;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.system.UserVO;

/*
 *@title UserService
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/14 11:37
 */
public interface UserService {


    void changeUserStatus(Long id, String status);


    ListVO<UserVO> queryUserList(QueryUserListRequest request);


    void changeUserRole(Long id, String roleName);


    UserVO queryUserInfo(String token) throws Exception;


    String login(String userId, String password, String code);


    void create(String userId, String username, String password, String roleName, String tenantIds);


    void update(String userId, String username, String password, String roleName, String tenantIds);


    void delete(String userId);


    void changePassword(String userId, String newPassword, String oldPassword);

    void register(String userId, String username, String password, String email, String code);

    void joinTenant(String inviteCode, String userId);
}

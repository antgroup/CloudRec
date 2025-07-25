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
package com.alipay.application.service.system.domain;


import com.alipay.application.service.system.domain.enums.RoleNameType;
import com.alipay.application.service.system.domain.enums.Status;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class User {
    private Long id;

    private Date gmtCreate;

    private Date gmtModified;

    private String username;

    private String userId;

    private Status status;

    private Long tenantId;

    private RoleNameType roleName;

    private String password;

    private Date lastLoginTime;

    /**
     * The user's currently selected tenant role name
     */
    private String selectTenantRoleName;

    public static final String DEFAULT_USER_ID = "cloudrec";
    private static final String DEFAULT_USER_PASSWORD = "cloudrec";

    public void changeStatus(Long id, Status status) {
        this.id = id;
        this.status = status;
    }

    public void changeRole(Long id, RoleNameType roleName) {
        this.id = id;
        this.roleName = roleName;
    }

    public void refreshLastLoginTime() {
        this.lastLoginTime = new Date();
    }

    public static User createDefaultUser() {
        User user = new User();
        user.setUserId(DEFAULT_USER_ID);
        user.setPassword(DEFAULT_USER_PASSWORD);
        user.setUsername(DEFAULT_USER_ID);
        user.setRoleName(RoleNameType.admin);
        user.setStatus(Status.valid);
        return user;
    }

}
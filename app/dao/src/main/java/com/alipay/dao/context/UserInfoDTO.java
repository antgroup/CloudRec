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
package com.alipay.dao.context;

import com.alipay.dao.dto.PageDTO;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserInfoDTO extends PageDTO {

    /**
     * user 表主键id
     */
    private Long uid;

    /**
     * 租户名称
     */
    private String tenantName;


    /**
     * 当租户为全局租户时，tenantId 为null
     */
    private Long tenantId;

    /**
     * 当租户是全局租户时，globalTenantId 不为null
     */
    private Long globalTenantId;

    /**
     * 登录id
     */
    private String userId;

    /**
     * 用户名
     */
    private String username;


    /**
     * 获取租户id
     *
     * @return 租户id
     */
    public Long getUserTenantId() {
        return this.globalTenantId != null ? this.globalTenantId : this.tenantId;
    }

    @Override
    public String toString() {
        return "UserInfoDTO{" +
                "uid=" + uid +
                ", tenantName='" + tenantName + '\'' +
                ", tenantId=" + tenantId +
                ", globalTenantId=" + globalTenantId +
                ", userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                '}';
    }
}

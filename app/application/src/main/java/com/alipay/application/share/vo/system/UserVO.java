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
package com.alipay.application.share.vo.system;

import com.alipay.application.service.system.domain.enums.RoleNameType;
import com.alipay.dao.po.UserPO;
import com.alipay.application.service.system.domain.User;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.BeanUtils;

import java.util.Date;

@Data
public class UserVO {
    private Long id;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtCreate;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtModified;

    /**
     * user name
     */
    private String username;

    /**
     * user id
     */
    private String userId;

    /**
     * user account status
     */
    private String status;

    /**
     * Currently selected tenant id
     */
    private Long tenantId;

    /**
     * Currently selected tenant name
     */
    private String tenantName;

    /**
     * Platform administrator or platform user
     */
    private String roleName;

    /**
     * The user's currently selected tenant role name
     */
    private String selectTenantRoleName;

    /**
     * token
     */
    private String token;

    /**
     * password
     */
    private String password;

    /**
     * Last login time
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date lastLoginTime;

    private String tenantIds;

    public static UserVO toVo(User user) {
        if (user == null) {
            return null;
        }

        UserVO userVO = new UserVO();
        BeanUtils.copyProperties(user, userVO);
        userVO.setStatus(user.getStatus().name());
        userVO.setRoleName(user.getRoleName().name());
        return userVO;
    }

    public static UserVO toVo(UserPO user) {
        if (user == null) {
            return null;
        }

        UserVO userVO = new UserVO();
        BeanUtils.copyProperties(user, userVO);
        if (Strings.isBlank(userVO.getRoleName())){
            userVO.setRoleName(RoleNameType.user.name());
        }
        return userVO;
    }
}
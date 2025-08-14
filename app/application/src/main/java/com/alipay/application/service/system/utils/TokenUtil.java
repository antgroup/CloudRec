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
package com.alipay.application.service.system.utils;

import com.alipay.application.service.system.domain.User;
import com.alipay.application.service.system.domain.enums.RoleNameType;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.Date;

@Slf4j
public class TokenUtil {

    private static final long EXPIRE_TIME = 24L * 60 * 60 * 1000 * 31 * 12;

    public static String sign(String username, String userId, String roleName) {
        return sign(username, userId, roleName, EXPIRE_TIME);
    }

    public static String sign(String username, String userId, long expireTime) {
        String token = null;
        try {
            Date expiresAt = new Date(System.currentTimeMillis() + expireTime);
            token = JWT.create().withIssuer("auth0").withClaim("username", username).withClaim("userId", userId)
                    .withExpiresAt(expiresAt).sign(Algorithm.HMAC256(SecretKeyUtil.JWT_SECRET_KEY_ENCRYPT_VALUE));
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return token;
    }

    public static String sign(String username, String userId, String roleName, long expireTime) {
        if (StringUtils.isEmpty(roleName)) {
            roleName = RoleNameType.user.name();
        }
        String token = null;
        try {
            Date expiresAt = new Date(System.currentTimeMillis() + expireTime);
            token = JWT.create().withIssuer("auth0").withClaim("username", username).withClaim("userId", userId)
                    .withClaim("roleName", roleName).withExpiresAt(expiresAt)
                    .sign(Algorithm.HMAC256(SecretKeyUtil.JWT_SECRET_KEY_ENCRYPT_VALUE));
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return token;
    }

    public static User parseToken(String token) {
        try {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SecretKeyUtil.JWT_SECRET_KEY_ENCRYPT_VALUE))
                    .withIssuer("auth0").build();
            DecodedJWT jwt = verifier.verify(token);

            User user = new User();
            user.setUsername(jwt.getClaim("username").asString());
            user.setUserId(jwt.getClaim("userId").asString());

            String roleName = jwt.getClaim("roleName").asString();
            RoleNameType role = RoleNameType.getRole(roleName);
            user.setRoleName(role);
            return user;
        } catch (Exception e) {
            return null;
        }
    }
}
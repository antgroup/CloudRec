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
package com.alipay.common.exception;


import java.util.Objects;

/*
 *@title BizErrorCodeEnum
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/2/8 11:25
 */
public enum BizErrorCodeEnum implements ErrorCode {

    /**
     * 未指明的异常
     */
    UNSPECIFIED("500", "服务器异常"),

    // 403
    FORBIDDEN("403", "无权限"),

    NO_SERVICE("404", "网络异常, 服务器熔断"),

    // 通用异常
    REQUEST_ERROR("400", "入参异常,请检查入参后再次调用"),
    ;

    /**
     * 错误码
     */
    private final String code;

    /**
     * 描述
     */
    private final String description;

    /**
     * 根据编码查询枚举。
     *
     * @param code 编码。
     * @return 枚举。
     */
    public static BizErrorCodeEnum getByCode(String code) {
        for (BizErrorCodeEnum value : BizErrorCodeEnum.values()) {
            if (Objects.equals(code, value.getCode())) {
                return value;
            }
        }
        return UNSPECIFIED;
    }

    /**
     * 枚举是否包含此code
     *
     * @param code 枚举code
     * @return 结果
     */
    public static Boolean contains(String code) {
        for (BizErrorCodeEnum value : BizErrorCodeEnum.values()) {
            if (Objects.equals(code, value.getCode())) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param code        错误码
     * @param description 描述
     */
    private BizErrorCodeEnum(final String code, final String description) {
        this.code = code;
        this.description = description;
    }

    @Override
    public String getCode() {
        return code;
    }

    @Override
    public String getDescription() {
        return description;
    }
}

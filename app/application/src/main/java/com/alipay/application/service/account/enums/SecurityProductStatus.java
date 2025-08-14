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
package com.alipay.application.service.account.enums;


import com.alipay.common.exception.StatusNotFindException;

/*
 *@title SecurityProductStatus
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/4/10 11:06
 */
public enum SecurityProductStatus {

    // 云产品开通状态：开通
    open,
    // 云产品开通状态：关闭
    close,
    ;

    SecurityProductStatus() {
    }

    public static SecurityProductStatus getEnumByCode(String code) {
        for (SecurityProductStatus status : values()) {
            if (status.name().equals(code)) {
                return status;
            }
        }
        return null;
    }


    public static boolean exist(String status) {
        for (SecurityProductStatus statusEnum : SecurityProductStatus.values()) {
            if (statusEnum.name().equals(status)) {
                return true;
            }
        }
        throw new StatusNotFindException();
    }
}

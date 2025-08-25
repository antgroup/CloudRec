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
package com.alipay.common.enums;

import com.alipay.common.exception.StatusNotFindException;

/*
 *@title Status
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/13 17:58
 */
public enum Status {

    // 有效
    valid,

    // 无效
    invalid,

    // 异常
    unusual,

    // 入队
    // inQueue,

    // 运行
    running,

    // 等待
    waiting,

    // 退出
    exit;

    /**
     * 判断
     */
    public static boolean exist(String status) {
        for (Status statusEnum : Status.values()) {
            if (statusEnum.name().equals(status)) {
                return true;
            }
        }
        throw new StatusNotFindException();
    }
}

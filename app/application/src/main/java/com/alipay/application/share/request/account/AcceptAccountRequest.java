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
package com.alipay.application.share.request.account;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

/*
 *@title TempAcceptAccountRequest
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/11/22 20:50
 */
@Getter
@Setter
public class AcceptAccountRequest {

    @NotEmpty(message = "ak不能为空")
    private String ak;

    @NotEmpty(message = "sk不能为空")
    private String sk;

    @NotEmpty(message = "账号不能为空")
    private String account;

    private String email;

    private String owner;

    private String nickName;

    private String ciso;

    @NotEmpty(message = "yunid不能为空")
    private String yunid;
}

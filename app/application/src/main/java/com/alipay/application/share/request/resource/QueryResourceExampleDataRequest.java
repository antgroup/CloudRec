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
package com.alipay.application.share.request.resource;

import com.alipay.application.share.request.rule.LinkDataParam;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

/*
 *@title QueryResourceExampleDataRequest
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/9/3 14:35
 */
@Data
public class QueryResourceExampleDataRequest {

    /**
     * 平台
     */
    @NotEmpty(message = "平台不能为空")
    private String platform;

    /**
     * 资源类型
     */
    @NotEmpty(message = "资源类型不能为空")
    private List<String> resourceType;

    /**
     * 关联资产数据
     */
    private List<LinkDataParam> linkedDataList;


    /**
     * resourceId
     */
    private String resourceId;

}

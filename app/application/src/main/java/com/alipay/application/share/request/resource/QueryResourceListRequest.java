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

import lombok.Getter;
import lombok.Setter;

import java.util.List;

/*
 *@title QueryResourceListRequest
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/7/29 14:24
 */
@Getter
@Setter
public class QueryResourceListRequest {

    {
        this.size = 10;
        this.page = 1;
    }

    private Integer size;

    private Integer page;

    private String platform;

    private List<String> platformList;

    private List<List<String>> resourceTypeList;

    private String resourceType;

    private String cloudAccountId;

    private String address;

    private String resourceName;

    private String resourceId;

    private String searchParam;

    private String instance;

    private String customFieldValue;

    /**
     * Used to sort by a specific field
     */
    private String sortParam;

    /**
     * ASC OR DESC
     */
    private String sortType;

    /**
     * Aggregation type for asset grouping
     * RESOURCE_TYPE: Group by resource type
     * CLOUD_ACCOUNT: Group by cloud account
     */
    private String aggregationType;
}

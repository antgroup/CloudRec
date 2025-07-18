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
package com.alipay.application.service.resource;

import com.alipay.application.share.request.base.IdListRequest;
import com.alipay.application.share.request.resource.QueryResourceExampleDataRequest;
import com.alipay.application.share.request.resource.QueryResourceListRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.resource.ResourceGroupTypeVO;
import com.alipay.application.share.vo.resource.ResourceInstanceVO;
import com.alipay.application.share.vo.resource.ResourceRiskCountVO;
import com.alipay.dao.dto.IQueryResourceDTO;
import com.alipay.dao.dto.ResourceAggByInstanceTypeDTO;
import com.alipay.dao.dto.ResourceDTO;
import com.alipay.dao.po.CloudResourceInstancePO;
import com.alipay.dao.po.ResourcePO;

import java.util.List;

/*
 *@title IQueryReource
 *@description 资源查询接口
 *@author jietian
 *@version 1.0
 *@create 2023/12/19 14:45
 */

public interface IQueryResource {


    List<CloudResourceInstancePO> queryByCond(String platform, String resourceType, String cloudAccountId);

    List<CloudResourceInstancePO> queryByCond(String platform,
                                              String resourceType,
                                              String cloudAccountId,
                                              Long scrollId,Integer size);


    List<CloudResourceInstancePO> queryByCond(String platform, String resourceType, String cloudAccountId, Integer limit);


    CloudResourceInstancePO queryResource(IQueryResourceDTO request);


    CloudResourceInstancePO query(String platform, String resourceType, String cloudAccountId, String resourceId);


    long queryResourceCount(String cloudAccount);


    ApiResponse<List<ResourcePO>> queryTypeList(String platform);


    ApiResponse<ListVO<ResourceInstanceVO>> queryResourceList(QueryResourceListRequest queryResourceListRequest);


    ResourceInstanceVO queryResourceDetail(Long id);


    ApiResponse<List<ResourceGroupTypeVO>> queryGroupTypeList(List<String> platformList);


    ApiResponse<Object> queryResourceExampleData(QueryResourceExampleDataRequest queryResourceExampleDataRequest);


    ApiResponse<ListVO<ResourceAggByInstanceTypeDTO>> queryAggregateAssets(ResourceDTO resourceDTO);


    ApiResponse<List<ResourceRiskCountVO>> queryResourceRiskQuantity(IdListRequest idListRequest);
}

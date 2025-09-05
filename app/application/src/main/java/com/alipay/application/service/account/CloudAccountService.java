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
package com.alipay.application.service.account;

import com.alipay.application.share.request.account.CreateCollectTaskRequest;
import com.alipay.application.share.request.account.QueryCloudAccountListRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.account.CloudAccountVO;
import com.alipay.dao.dto.CloudAccountDTO;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/*
 *@title CloudAccountService
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/20 10:57
 */
public interface CloudAccountService {

    ApiResponse<ListVO<CloudAccountVO>> queryCloudAccountList(CloudAccountDTO cloudAccountDTO);


    ApiResponse<String> saveCloudAccount(CloudAccountDTO cloudAccountDTO);


    ApiResponse<String> removeCloudAccount(Long id) throws IOException;


    ApiResponse<CloudAccountVO> queryCloudAccountDetail(Long id);


    void updateCloudAccountStatus(String cloudAccountId, String accountStatus);


    ApiResponse<Map<String, Object>> queryCloudAccountBaseInfoList(QueryCloudAccountListRequest request);


    ApiResponse<List<Map<String, Object>>> queryCloudAccountBaseInfoListV2(QueryCloudAccountListRequest request);


    void createCollectTask(CreateCollectTaskRequest request);
}

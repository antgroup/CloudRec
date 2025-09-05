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
package com.alipay.application.service.collector;

import com.alipay.application.service.collector.domain.CollectRecordInfo;
import com.alipay.application.service.collector.domain.TaskResp;
import com.alipay.application.share.request.collector.AcceptSupportResourceTypeRequest;
import com.alipay.application.share.request.collector.LogRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.collector.AgentCloudAccountVO;
import com.alipay.application.share.vo.collector.AgentRegistryVO;
import com.alipay.application.share.vo.collector.OnceTokenVO;
import com.alipay.application.share.vo.collector.Registry;
import com.alipay.dao.dto.AgentRegistryDTO;
import com.alipay.dao.po.AgentRegistryPO;

import java.util.List;

/*
 *@title AgentService
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/8/13 14:19
 */
public interface AgentService {

    ApiResponse<Registry.RegistryResponse> registry(Registry registry, String token);


    ApiResponse<ListVO<AgentRegistryVO>> queryAgentList(AgentRegistryDTO dto);


    OnceTokenVO getOnceToken(String userId);


    void checkOnceToken(Registry registry, String token);


    AgentRegistryPO checkPersistentToken(String platform, String registryValue, String token);

    void runningStartSignal(String token, String cloudAccountId, CollectRecordInfo collectRecordInfo);

    void runningFinishSignal(String cloudAccountId, Long taskId);


    ApiResponse<List<AgentCloudAccountVO>> queryCloudAccountList(String persistentToken, String registryValue,
                                                                 String platform, List<String> sites, List<Long> taskIds, Integer freeCloudAccountCount);

    void exitAgent(String onceToken);


    void acceptSupportResourceType(AcceptSupportResourceTypeRequest request);


    void log(LogRequest logRequest);


    void HealthCheck();


    void initCloudAccountCollectStatus();

    List<TaskResp> listCollectorTask(String persistentToken, String registryValue, String platform) throws Exception;

}

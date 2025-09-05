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
package com.alipay.application.service.rule;

import com.alipay.application.share.request.base.IdRequest;
import com.alipay.application.share.request.rule.ChangeStatusRequest;
import com.alipay.application.share.request.rule.ListRuleRequest;
import com.alipay.application.share.request.rule.SaveRuleRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleTypeVO;
import com.alipay.application.share.vo.rule.RuleVO;

import java.io.IOException;
import java.util.List;

/*
 *@title RuleService
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/5 16:45
 */
public interface RuleService {


    ApiResponse<String> saveRule(SaveRuleRequest saveRuleRequest) throws IOException;


    ApiResponse<ListVO<RuleVO>> queryRuleList(ListRuleRequest listRuleRequest);

    ListVO<RuleVO> queryEffectRuleList(ListRuleRequest listRuleRequest);


    ApiResponse<String> deleteRule(Long id);


    ApiResponse<String> changeRuleStatus(ChangeStatusRequest changeRuleStatusRequest);


    ApiResponse<String> copyRule(IdRequest idRequest);


    ApiResponse<RuleVO> queryRuleDetail(IdRequest idRequest);


    ApiResponse<List<RuleTypeVO>> queryRuleTypeList();


    List<String> queryRuleTypeNameList(Long ruleId);


    List<String> queryRuleNameList();

    String generateRuleCode(String platform, String resourceType);

    List<RuleVO> queryAllRuleList();

    ApiResponse<String> addTenantSelectRule(String ruleCode);

    ApiResponse<String> deleteTenantSelectRule(String ruleCode);

    ApiResponse<String> batchDeleteTenantSelectRule(List<String> ruleCodeList);

    List<RuleVO> queryAllTenantSelectRuleList();

    ApiResponse<String> batchAddTenantSelectRule(List<String> ruleCodeList);
}

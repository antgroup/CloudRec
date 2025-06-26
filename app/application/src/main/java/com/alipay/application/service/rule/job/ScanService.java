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
package com.alipay.application.service.rule.job;

import com.alipay.application.service.rule.domain.RuleAgg;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.dao.po.CloudAccountPO;

/*
 *@title ScanService
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/18 09:12
 */
public interface ScanService {


    /**
     * 按照风险组扫描
     *
     * @param groupId groupId
     */
    void scanByGroup(Long groupId);


    void shardingScanAll();

    /**
     * 扫描全部
     */
    void scanAll();

    /**
     * 扫描指定云账号、全部规则
     *
     * @param platform       platform
     * @param cloudAccountId cloudAccountId
     */
    //void scanAll(String platform, String cloudAccountId);

    /**
     * 扫描指定规则、指定账号的数据
     *
     * @param ruleAgg        RuleAgg
     * @param cloudAccountPO cloudAccountPO
     * @throws Exception Exception
     */
    void scanByRule(RuleAgg ruleAgg, CloudAccountPO cloudAccountPO) throws Exception;

    /**
     * 扫描指定规则的数据
     *
     * @param ruleId ruleId
     * @return ApiResponse<String>
     */
    ApiResponse<String> scanByRule(Long ruleId);
}

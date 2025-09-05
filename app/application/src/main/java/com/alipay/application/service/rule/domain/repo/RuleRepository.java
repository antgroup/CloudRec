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
package com.alipay.application.service.rule.domain.repo;


import com.alipay.application.service.rule.domain.GlobalVariable;
import com.alipay.application.service.rule.domain.RuleAgg;

import java.util.List;

/*
 *@title RuleRepository
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/3/12 10:44
 */
public interface RuleRepository {

    List<RuleAgg> findAll();

    List<RuleAgg> findByIdList(List<Long> idList);

    List<RuleAgg> findAll(String platform);

    RuleAgg findByRuleId(Long ruleId);

    List<RuleAgg> findByGroupId(Long groupId, String status);

    void save(RuleAgg ruleAgg);

    void saveOrgRule(RuleAgg ruleAgg);

    /**
     * Find rules synchronized from rule central warehouse
     *
     * @return ruleAgg List
     */
    List<RuleAgg> findRuleListFromGitHub();

    /**
     * Find rules synchronized from local file
     *
     * @return ruleAgg List
     */
    List<RuleAgg> findRuleListFromLocalFile();

    /**
     * Association rules and global variables
     *
     * @param id              rule id
     * @param globalVariables global variables
     */
    void relatedGlobalVariables(Long id, List<GlobalVariable> globalVariables);


    /**
     * Is there a new rule
     *
     * @return int new rule count
     */
    int existNewRule();
}

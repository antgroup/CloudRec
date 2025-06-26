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
package com.alipay.application.service.rule.exposed;


import java.util.List;

/*
 *@title InitRuleService
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/3/17 16:53
 */
public interface InitRuleService {

    /**
     * 初始化规则类型
     */
    void initRuleType();

    /**
     * 从远程仓库加载规则
     */
    void loadRuleFromGithub(Boolean coverage);

    /**
     * 从本地文件系统加载规则
     */
    void loadRuleFromLocalFile();

    /**
     * 将规则从数据库中写如代码文件中
     */
    String writeRule(List<Long> idList);
}

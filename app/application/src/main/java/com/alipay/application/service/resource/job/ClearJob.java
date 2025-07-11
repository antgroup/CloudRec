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
package com.alipay.application.service.resource.job;


/*
 *@title ClearJob
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/12/31 10:33
 */
public interface ClearJob {

    /**
     * 系统清理废弃数据
     */
    void clearObsoleteData();

    /**
     * 云账号采集完成后，正式提交删除资源
     * @param cloudAccountId 云账号ID
     */
    void commitDeleteResourceByCloudAccount(String cloudAccountId);

    /**
     * 缓存清理
     */
    void cacheClearHandler();
}

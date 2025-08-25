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
package com.alipay.application.service.resource.identitySecurity;

import com.alipay.application.share.request.resource.QueryIdentityRuleRequest;
import com.alipay.application.share.request.resource.QueryIdentityCardRequest;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.resource.IdentityCardVO;
import com.alipay.application.share.vo.resource.IdentitySecurityRiskInfoVO;
import com.alipay.application.share.vo.resource.IdentitySecurityVO;
import com.alipay.dao.po.PlatformPO;

import java.util.List;

/**
 * Date: 2025/4/23
 * Author: lz
 */
public interface IdentitySecurityService {

    /**
     * 身份模块标签列表
     * @return
     */
    List<String> getTagList();

    ListVO<IdentitySecurityVO> queryIdentitySecurityList(QueryIdentityRuleRequest request);

    IdentitySecurityVO queryIdentitySecurityDetail(Long id);

    List<IdentitySecurityRiskInfoVO> queryRiskInfo(QueryIdentityRuleRequest request);

    List<PlatformPO> getPlatformList();

    List<IdentityCardVO> queryIdentityCardListWithRulds(QueryIdentityCardRequest request);
}

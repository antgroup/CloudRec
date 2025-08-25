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

import com.alipay.application.share.request.rule.SaveWhitedRuleRequest;
import com.alipay.application.share.request.rule.TestRunWhitedRuleRequestDTO;
import com.alipay.application.share.request.rule.TestRunWhitedRuleResultDTO;
import com.alipay.application.share.request.rule.WhitedScanInputDataDTO;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.whited.GroupByRuleCodeVO;
import com.alipay.application.share.vo.whited.WhitedConfigVO;
import com.alipay.application.share.vo.whited.WhitedRuleConfigVO;
import com.alipay.dao.dto.QueryWhitedRuleDTO;

import java.io.IOException;
import java.util.List;

/**
 * Date: 2025/3/13
 * Author: lz
 */
public interface WhitedRuleService {

    Long save(SaveWhitedRuleRequest dto) throws IOException;

    ListVO<WhitedRuleConfigVO> getList(QueryWhitedRuleDTO dto);

    WhitedRuleConfigVO getById(Long id);

    int deleteById(Long id);

    void changeStatus(Long id, int enable);

    void grabLock(Long id);

    List<WhitedConfigVO> getWhitedConfigList();

    WhitedScanInputDataDTO queryExampleData(String riskRuleCode);

    TestRunWhitedRuleResultDTO testRun(TestRunWhitedRuleRequestDTO dto);

    SaveWhitedRuleRequest queryWhitedContentByRisk(Long riskId);

    ListVO<GroupByRuleCodeVO> getListGroupByRuleCode(QueryWhitedRuleDTO dto);
}

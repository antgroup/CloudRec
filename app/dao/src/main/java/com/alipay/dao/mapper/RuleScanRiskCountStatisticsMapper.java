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
package com.alipay.dao.mapper;

import com.alipay.dao.po.RuleScanRiskCountStatisticsPO;
import org.apache.ibatis.annotations.Param;

import java.util.Date;

public interface RuleScanRiskCountStatisticsMapper {
    int deleteByPrimaryKey(Long id);

    int insert(RuleScanRiskCountStatisticsPO row);

    int insertSelective(RuleScanRiskCountStatisticsPO row);

    RuleScanRiskCountStatisticsPO selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(RuleScanRiskCountStatisticsPO row);

    int updateByPrimaryKey(RuleScanRiskCountStatisticsPO row);

    int deleteByRuleIdAndTenantId(@Param("ruleId") Long ruleId, @Param("tenantId") Long tenantId);

    /**
     * 根据租户ID查询风险统计总数
     *
     * @param tenantId 租户ID
     * @return 风险统计总数
     */
    long findSumCount(Long tenantId);

    int deleteByDate(Date yesterdayEndTime);
}
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

import com.alipay.dao.dto.*;
import com.alipay.dao.po.RuleScanResultPO;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface RuleScanResultMapper {

    int deleteByPrimaryKey(Long id);

    int insertSelective(RuleScanResultPO record);

    RuleScanResultPO selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(RuleScanResultPO record);

    RuleScanResultPO fineOne(@Param("resourceId") String resourceId,
                             @Param("cloudAccountId") String cloudAccountId,
                             @Param("ruleId") Long ruleId);


    RuleScanResultPO findOneJoinRule(@Param("resourceId") String resourceId,
                                     @Param("cloudAccountId") String cloudAccountId,
                                     @Param("ruleCode") String ruleCode);

    int deleteByCloudAccountId(String cloudAccountId);

    int findCount(RuleScanResultDTO dto);

    int findCountV2(RuleScanResultDTO dto);

    int findCountByTenant(@Param("ruleId") Long ruleId, @Param("status") String status, @Param("tenantId") Long tenantId);


    List<RuleScanResultPO> findList(RuleScanResultDTO dto);

    List<RuleScanResultPO> findListV2(RuleScanResultDTO dto);

    List<RuleScanResultPO> findIdList(RuleScanResultDTO dto);

    /**
     * Scan the result list based on conditional query rules
     *
     * @param ruleId     rule id
     * @param statusList status list
     * @return Rule scan result list
     */
    List<RuleScanResultPO> find(@Param("ruleId") Long ruleId,
                                @Param("cloudAccountId") String cloudAccountId,
                                @Param("statusList") List<String> statusList,
                                @Param("nextVersion") Long nextVersion);

    /**
     * Query the maximum version number of the specified rule ID
     *
     * @param ruleId rule id
     * @return MAX version number
     */
    Long findMaxVersion(@Param("ruleId") Long ruleId, @Param("cloudAccountId") String cloudAccountId);

    /**
     * 根据规则ID删除
     *
     * @param ruleId 规则ID
     */
    int deleteByRuleId(Long ruleId);

    /**
     * 查询风险类型数量
     *
     * @param riskLevel 风险等级
     * @param tenantId  tenantId
     * @return 风险类型数量
     */
    List<HomeTopRiskDTO> findRiskCountGroupByRuleType(@Param("riskLevel") String riskLevel,
                                                      @Param("tenantId") Long tenantId, @Param("statusList") List<String> statusList,
                                                      @Param("limit") Integer limit);



    /**
     * 查询高、中、低风险数
     *
     * @param dto dto
     * @return 风险总数、高风险数、中风险数、低风险数
     */
    RiskCountDTO findRiskCount(RuleScanResultDTO dto);


    /**
     * 删除风险信息
     *
     * @param platform     平台表示
     * @param resourceType 资产标识
     * @return 删除数量
     */
    int deleteRisk(@Param("platform") String platform, @Param("resourceType") String resourceType);

    /**
     * 滚动查询
     *
     * @param dto 请求参数
     * @return 规则扫描结果
     */
    List<RuleScanResultPO> findListWithScrollId(QueryScanResultDTO dto);

    List<RuleScanResultPO> findBaseInfoWithScrollId(QueryScanResultDTO dto);

    void updateResourceStatus(@Param("cloudResourceInstanceIds") List<Long> cloudResourceInstanceIds, @Param("resourceStatus") String resourceStatus);

    List<RuleStatisticsDTO> listRuleStatistics(RuleScanResultDTO dto);

    int deleteByRuleIdAndTenantId(@Param("ruleId") Long ruleId,@Param("tenantId") Long tenantId);

    List<CloudAccountStatisticsDTO> listCloudAccountStatistics(RuleScanResultDTO dto);

    List<ResourceTypeStatisticsDTO> listResourceTypeStatistics(RuleScanResultDTO dto);
}
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
package com.alipay.application.service.risk;

import com.alibaba.excel.EasyExcel;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.alipay.application.service.common.CloudAccount;
import com.alipay.application.service.common.utils.CacheUtil;
import com.alipay.application.service.common.utils.DBDistributedLockUtil;
import com.alipay.application.service.common.utils.DbCacheUtil;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleScanResultExportVO;
import com.alipay.application.share.vo.rule.RuleScanResultVO;
import com.alipay.common.exception.BizException;
import com.alipay.common.exception.RoleCheckException;
import com.alipay.common.utils.ExcelUtils;
import com.alipay.common.utils.ListUtils;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.dto.RuleStatisticsDTO;
import com.alipay.dao.mapper.RuleScanResultMapper;
import com.alipay.dao.po.DbCachePO;
import com.alipay.dao.po.RuleScanResultPO;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/*
 *@title RiskServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/7/16 16:43
 */
@Slf4j
@Service
public class RiskServiceImpl implements RiskService {

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private DBDistributedLockUtil dbDistributedLockUtil;

    @Resource
    private RiskStatusManager riskStatusManager;

    @Resource
    private CloudAccount cloudAccount;

    @Resource
    private DbCacheUtil dbCacheUtil;

    private static final String dbCacheKey = "risk::query_risk_list";

    private static final String dbCacheKey_agg = "risk::query_risk_list_agg";

    private static final String localLockPrefix = "risk::export_risk_list";

    @Override
    public ApiResponse<ListVO<RuleScanResultVO>> queryRiskList(RuleScanResultDTO ruleScanResultDTO) {

        boolean needCache = false;
        String key = CacheUtil.buildKey(dbCacheKey, UserInfoContext.getCurrentUser().getUserTenantId(), ruleScanResultDTO.getStatus(), ruleScanResultDTO.getPage(), ruleScanResultDTO.getSize());
        if (judgeCacheCond(ruleScanResultDTO)) {
            needCache = true;
            DbCachePO dbCachePO = dbCacheUtil.get(key);
            if (dbCachePO != null) {
                ListVO<RuleScanResultVO> listVO = JSON.parseObject(dbCachePO.getValue(), new TypeReference<>() {
                });
                return new ApiResponse<>(listVO);
            }
        }

        ruleScanResultDTO.setCloudAccountIdList(cloudAccount.queryCloudAccountIdList(ruleScanResultDTO.getCloudAccountId()));
        ruleScanResultDTO.setTenantId(UserInfoContext.getCurrentUser().getTenantId());

        ListVO<RuleScanResultVO> listVO = new ListVO<>();
        int count = ruleScanResultMapper.findCount(ruleScanResultDTO);
        if (count == 0) {
            return new ApiResponse<>(listVO);
        }

        ruleScanResultDTO.setOffset();
        List<RuleScanResultPO> list = ruleScanResultMapper.findList(ruleScanResultDTO);
        List<RuleScanResultVO> collect = list.stream().parallel().map(RuleScanResultVO::buildList).toList();

        listVO.setTotal(count);
        listVO.setData(collect);

        if (needCache) {
            dbCacheUtil.put(key, listVO);
        }
        return new ApiResponse<>(listVO);
    }

    @Override
    public void exportRiskList(HttpServletResponse response, RuleScanResultDTO dto) throws IOException {
        if (!dbDistributedLockUtil.tryLock(localLockPrefix + UserInfoContext.getCurrentUser().getUserId(), 1000 * 60 * 60)) {
            throw new BizException("Exporting, please try again later");
        }
        try {
            List<String> cloudAccountIdList = cloudAccount.queryCloudAccountIdList(dto.getCloudAccountId());
            dto.setCloudAccountIdList(cloudAccountIdList);
            dto.setTenantId(UserInfoContext.getCurrentUser().getTenantId());
            int count = ruleScanResultMapper.findCount(dto);
            if (count >= 100000) {
                throw new BizException("The exported data volume exceeds 100,000, please go offline to export");
            }

            final int maxSize = 1000;
            dto.setPage(1);
            dto.setSize(maxSize);
            List<RuleScanResultExportVO> result = new ArrayList<>(10000);
            while (true) {
                dto.setOffset();
                List<RuleScanResultPO> list = ruleScanResultMapper.findList(dto);
                List<RuleScanResultExportVO> collect = list.parallelStream().map(RuleScanResultExportVO::po2vo).toList();
                result.addAll(collect);
                if (list.size() < maxSize) {
                    break;
                }

                dto.setPage(dto.getPage() + 1);
            }

            ExcelUtils.resetCellMaxTextLength();
            response.setCharacterEncoding("utf-8");
            String fileName = URLEncoder.encode("CloudRec-Risk-Data.xlsx", StandardCharsets.UTF_8).replaceAll("\\+", "%20");
            response.setHeader("Content-disposition", "attachment;filename*=utf-8''" + fileName + ".xlsx");

            EasyExcel.write(response.getOutputStream(), RuleScanResultExportVO.class).sheet("sheet1").doWrite(result);
        } catch (Exception e) {
            log.error("exportRiskList error", e);
        } finally {
            dbDistributedLockUtil.releaseLock(localLockPrefix + UserInfoContext.getCurrentUser().getUserId());
        }
    }


    /**
     * Query and check rule scan results
     *
     * @param riskId RiskID
     * @return RuleScanResultPO rule scan results
     */
    private RuleScanResultPO queryDetail(Long riskId) {
        RuleScanResultPO ruleScanResultPO = ruleScanResultMapper.selectByPrimaryKey(riskId);

        if (ruleScanResultPO == null) {
            throw new BizException("Risk ID not found");
        }

        Long tenantId = UserInfoContext.getCurrentUser().getTenantId();
        if (tenantId == null) {
            return ruleScanResultPO;
        }

        // If the tenant ID does not match, an exception is thrown
        if (!tenantId.equals(ruleScanResultPO.getTenantId())) {
            throw new RoleCheckException("Tenant not match");
        }

        return ruleScanResultPO;
    }

    @Override
    public ApiResponse<RuleScanResultVO> queryRiskDetail(Long riskId) {
        RuleScanResultPO ruleScanResultPO = queryDetail(riskId);
        RuleScanResultVO ruleScanResultVO = RuleScanResultVO.buildDetail(ruleScanResultPO);

        return new ApiResponse<>(ruleScanResultVO);
    }

    @Override
    public ApiResponse<String> ignoreRisk(Long riskId, String ignoreReason, String ignoreReasonType) {
        RuleScanResultPO ruleScanResultPO = queryDetail(riskId);

        riskStatusManager.unrepairedToIgnored(ruleScanResultPO.getId(), UserInfoContext.getCurrentUser().getUserId(), ignoreReasonType, ignoreReason);

        dbCacheUtil.clear(dbCacheKey);

        return ApiResponse.SUCCESS;
    }

    @Override
    public ApiResponse<String> cancelIgnoreRisk(RuleScanResultDTO dto) {
        RuleScanResultPO ruleScanResultPO = queryDetail(dto.getId());

        RiskStatusManager riskStatusManager = SpringUtils.getApplicationContext().getBean(RiskStatusManager.class);
        riskStatusManager.ignoredToUnrepaired(ruleScanResultPO.getId(), UserInfoContext.getCurrentUser().getUserId());

        dbCacheUtil.clear(dbCacheKey);

        return ApiResponse.SUCCESS;
    }


    private boolean judgeCacheCond(RuleScanResultDTO ruleScanResultDTO) {
        return ListUtils.isEmpty(ruleScanResultDTO.getPlatformList())
                && ListUtils.isEmpty(ruleScanResultDTO.getRiskLevelList())
                && ListUtils.isEmpty(ruleScanResultDTO.getRuleCodeList())
                && ListUtils.isEmpty(ruleScanResultDTO.getRuleGroupIdList())
                && ListUtils.isEmpty(ruleScanResultDTO.getResourceTypeList())
                && ListUtils.isEmpty(ruleScanResultDTO.getRuleTypeIdList())
                && ListUtils.isEmpty(ruleScanResultDTO.getRuleIdList())
                && StringUtils.isEmpty(ruleScanResultDTO.getCloudAccountId())
                && StringUtils.isEmpty(ruleScanResultDTO.getResourceId())
                && StringUtils.isEmpty(ruleScanResultDTO.getResourceName())
                && StringUtils.isEmpty(ruleScanResultDTO.getGmtCreateStart())
                && StringUtils.isEmpty(ruleScanResultDTO.getGmtCreateEnd())
                && StringUtils.isEmpty(ruleScanResultDTO.getGmtModifiedStart())
                && StringUtils.isEmpty(ruleScanResultDTO.getGmtModifiedEnd())
                && StringUtils.isEmpty(ruleScanResultDTO.getResourceStatus());
    }

    /**
     *
     */
    @Override
    public List<RuleStatisticsDTO> listRuleStatistics(RuleScanResultDTO ruleScanResultDTO) {
        boolean needCache = false;
        String key = CacheUtil.buildKey(dbCacheKey_agg, UserInfoContext.getCurrentUser().getUserTenantId());
        if (judgeCacheCond(ruleScanResultDTO)) {
            needCache = true;
            DbCachePO dbCachePO = dbCacheUtil.get(key);
            if (dbCachePO != null) {
                return JSON.parseObject(dbCachePO.getValue(), new TypeReference<>() {
                });
            }
        }
        if (ruleScanResultDTO.getCloudAccountId() != null) {
            ruleScanResultDTO.setCloudAccountIdList(cloudAccount.queryCloudAccountIdList(ruleScanResultDTO.getCloudAccountId()));
        }
        List<RuleStatisticsDTO> ruleStatisticsDTOS = ruleScanResultMapper.listRuleStatistics(ruleScanResultDTO);
        if (needCache) {
            dbCacheUtil.put(key, ruleStatisticsDTOS);
        }

        return ruleStatisticsDTOS;
    }

}


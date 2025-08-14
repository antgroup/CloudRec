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
package com.alipay.api.web.risk;

import com.alipay.api.config.filter.annotation.aop.AuthenticateToken;
import com.alipay.application.service.risk.RiskService;
import com.alipay.application.service.system.OperationLogService;
import com.alipay.application.share.request.risk.*;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleScanResultVO;
import com.alipay.application.share.vo.system.OperationLogVO;
import com.alipay.common.enums.IgnoreReasonType;
import com.alipay.common.enums.LogType;
import com.alipay.common.utils.ListUtils;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.context.UserInfoDTO;
import com.alipay.dao.dto.*;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.BeanUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;

/*
 *@title RiskController
 *@description 风险相关接口
 *@author jietian
 *@version 1.0
 *@create 2024/7/16 16:32
 */
@RestController
@RequestMapping("/api/risk")
@Validated
public class RiskController {

    @Resource
    private RiskService riskService;

    @Resource
    private OperationLogService operationLogService;


    @AuthenticateToken
    @PostMapping("/queryRiskList")
    public ApiResponse<ListVO<RuleScanResultVO>> queryRiskList(@RequestBody QueryRiskRequest queryRiskRequest) {

        RuleScanResultDTO dto = RuleScanResultDTO.builder().build();
        BeanUtils.copyProperties(queryRiskRequest, dto);
        dto.setResourceTypeList(ListUtils.setList(queryRiskRequest.getResourceTypeList()));
        dto.setRuleTypeIdList(ListUtils.setList(queryRiskRequest.getRuleTypeIdList()));

        return riskService.queryRiskList(dto);
    }


    @AuthenticateToken
    @PostMapping("/exportRiskList")
    public void exportRiskList(HttpServletResponse response, @RequestBody QueryRiskRequest queryRiskRequest) throws IOException {
        UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
        RuleScanResultDTO dto = RuleScanResultDTO.builder().build();
        BeanUtils.copyProperties(queryRiskRequest, dto);
        dto.setTenantId(currentUser.getTenantId());

        dto.setResourceTypeList(ListUtils.setList(queryRiskRequest.getResourceTypeList()));
        dto.setRuleTypeIdList(ListUtils.setList(queryRiskRequest.getRuleTypeIdList()));
        riskService.exportRiskList(response, dto);
    }

    @AuthenticateToken
    @PostMapping("/listRuleStatistics")
    public ApiResponse<List<RuleStatisticsDTO>> listRuleStatistics(@RequestBody QueryRiskRequest req) {
        RuleScanResultDTO dto = RuleScanResultDTO.builder().build();
        BeanUtils.copyProperties(req, dto);

        dto.setResourceTypeList(ListUtils.setList(req.getResourceTypeList()));
        dto.setRuleTypeIdList(ListUtils.setList(req.getRuleTypeIdList()));

        List<RuleStatisticsDTO> ruleNameDTOS = riskService.listRuleStatistics(dto);

        return new ApiResponse<>(ruleNameDTOS);
    }

    @AuthenticateToken
    @PostMapping("/listCloudAccountStatistics")
    public ApiResponse<List<CloudAccountStatisticsDTO>> listCloudAccountStatistics(@RequestBody QueryRiskRequest req) {
        RuleScanResultDTO dto = RuleScanResultDTO.builder().build();
        BeanUtils.copyProperties(req, dto);

        dto.setResourceTypeList(ListUtils.setList(req.getResourceTypeList()));
        dto.setRuleTypeIdList(ListUtils.setList(req.getRuleTypeIdList()));

        List<CloudAccountStatisticsDTO> ruleNameDTOS = riskService.listCloudAccountStatistics(dto);

        return new ApiResponse<>(ruleNameDTOS);
    }

    @AuthenticateToken
    @PostMapping("/listResourceTypeStatistics")
    public ApiResponse<List<ResourceTypeStatisticsDTO>> listResourceTypeStatistics(@RequestBody QueryRiskRequest req) {
        RuleScanResultDTO dto = RuleScanResultDTO.builder().build();
        BeanUtils.copyProperties(req, dto);

        dto.setResourceTypeList(ListUtils.setList(req.getResourceTypeList()));
        dto.setRuleTypeIdList(ListUtils.setList(req.getRuleTypeIdList()));

        List<ResourceTypeStatisticsDTO> ruleNameDTOS = riskService.listResourceTypeStatistics(dto);

        return new ApiResponse<>(ruleNameDTOS);
    }


    @AuthenticateToken
    @PostMapping("/queryRiskDetail")
    public ApiResponse<RuleScanResultVO> queryRiskDetail(@RequestBody QueryRiskDetailRequest req) {
        return riskService.queryRiskDetail(req.getRiskId());
    }


    @AuthenticateToken
    @PostMapping("/ignoreRisk")
    public ApiResponse<String> ignoreRisk(HttpServletRequest request,
                                          @Validated @RequestBody IgnoreRiskRequest req, BindingResult err) {
        if (err.hasErrors()) {
            return new ApiResponse<>(err);
        }

        if (!IgnoreReasonType.isIgnoreReason(req.getIgnoreReasonType())) {
            return new ApiResponse<>("ignoreReasonType is not valid");
        }

        return riskService.ignoreRisk(req.getRiskId(), req.getIgnoreReason(), req.getIgnoreReasonType());
    }


    @AuthenticateToken
    @PostMapping("/cancelIgnoreRisk")
    public ApiResponse<String> cancelIgnoreRisk(HttpServletRequest request,
                                                @Validated @RequestBody CancelIgnoreRiskRequest cancelIgnoreRiskRequest, BindingResult err) {
        if (err.hasErrors()) {
            return new ApiResponse<>(err);
        }
        RuleScanResultDTO dto = RuleScanResultDTO.builder().build();

        dto.setId(cancelIgnoreRiskRequest.getRiskId());
        return riskService.cancelIgnoreRisk(dto);
    }

    /**
     * Query the operation log of scan results
     */
    @PostMapping("/operationLog")
    public ApiResponse<List<OperationLogVO>> queryOperationLog(
            @Validated @RequestBody QueryOperationLogRequest queryOperationLogRequest, BindingResult err) {
        if (err.hasErrors()) {
            return new ApiResponse<>(err);
        }

        OperationLogDTO operationLogDTO = new OperationLogDTO();
        operationLogDTO.setCorrelationId(queryOperationLogRequest.getId());
        operationLogDTO.setType(LogType.RISK.name());
        return operationLogService.queryOperationLog(operationLogDTO);
    }

    /**
     * Comment risk information
     */
    @AuthenticateToken
    @PostMapping("/commentInformation")
    public ApiResponse<String> commentInformation(HttpServletRequest request,
                                                  @Validated @RequestBody CommentInformationRequest commentInformationRequest, BindingResult err) {
        if (err.hasErrors()) {
            return new ApiResponse<>(err);
        }

        OperationLogDTO operationLogDTO = new OperationLogDTO();
        operationLogDTO.setCorrelationId(commentInformationRequest.getId());
        operationLogDTO.setNotes(commentInformationRequest.getNotes());

        operationLogDTO.setUserId(UserInfoContext.getCurrentUser().getUserId());
        return operationLogService.commentInformation(operationLogDTO);
    }
}

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
package com.alipay.api.web.rule;

import com.alipay.api.config.filter.annotation.aop.AuthenticateToken;
import com.alipay.application.service.rule.WhitedRuleService;
import com.alipay.application.share.request.rule.*;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.EffectData;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.whited.GroupByRuleCodeVO;
import com.alipay.application.share.vo.whited.WhitedConfigVO;
import com.alipay.application.share.vo.whited.WhitedRuleConfigVO;
import com.alipay.common.enums.WhitedRuleOperatorEnum;
import com.alipay.common.enums.WhitedRuleTypeEnum;
import com.alipay.dao.dto.QueryWhitedRuleDTO;
import jakarta.annotation.Resource;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Date: 2025/3/13
 * Author: lz
 */
@RestController
@RequestMapping("/api/whitedRule")
@Validated
public class WhitedRuleController {

    @Resource
    private WhitedRuleService whitedRuleService;


    /**
     * 获取白名单配置列表参数
     *
     * @return
     */
    @GetMapping("/getWhitedConfigList")
    @AuthenticateToken
    public ApiResponse<List<WhitedConfigVO>> getWhitedConfigList() {
        return new ApiResponse<>(whitedRuleService.getWhitedConfigList());
    }


    /**
     * 保存白名单
     *
     * @param request
     * @return
     * @throws IOException
     */
    @AuthenticateToken
    @PostMapping("/save")
    public ApiResponse<EffectData> save(@RequestBody SaveWhitedRuleRequest request) throws IOException {
        if (!WhitedRuleTypeEnum.exist(request.getRuleType())) {
            throw new RuntimeException("ruleType must be RULE_ENGINE or REGO");
        }

        EffectData effectData = new EffectData();
        effectData.setEffectId(whitedRuleService.save(request));
        return new ApiResponse<>(effectData);
    }

    /**
     * 查询白名单列表
     *
     * @param request
     * @return
     * @throws IOException
     */
    @AuthenticateToken
    @PostMapping("/list")
    public ApiResponse<ListVO<WhitedRuleConfigVO>> list(@RequestBody QueryWhitedRuleRequest request) throws IOException {
        QueryWhitedRuleDTO dto = QueryWhitedRuleDTO.builder().build();
        BeanUtils.copyProperties(request, dto);
        ListVO<WhitedRuleConfigVO> listVO = whitedRuleService.getList(dto);
        return new ApiResponse<>(listVO);
    }


    @AuthenticateToken
    @PostMapping("/listGroupByRuleCode")
    public ApiResponse<ListVO<GroupByRuleCodeVO>> listGroupByRuleCode(@RequestBody QueryWhitedRuleRequest request) {
        QueryWhitedRuleDTO dto = QueryWhitedRuleDTO.builder().build();
        BeanUtils.copyProperties(request, dto);
        ListVO<GroupByRuleCodeVO> listVO = whitedRuleService.getListGroupByRuleCode(dto);
        return new ApiResponse<>(listVO);
    }


    /**
     * 白名单详情
     *
     * @param id
     * @return
     */
    @AuthenticateToken
    @GetMapping("/{id}")
    public ApiResponse<WhitedRuleConfigVO> detail(@PathVariable Long id) {
        WhitedRuleConfigVO whitedRuleConfigVO = whitedRuleService.getById(id);
        return new ApiResponse<>(whitedRuleConfigVO);
    }

    /**
     * 删除白名单
     *
     * @param id
     * @return
     */
    @AuthenticateToken
    @PostMapping("/delete/{id}")
    public ApiResponse<String> delete(@PathVariable Long id) {
        whitedRuleService.deleteById(id);
        return ApiResponse.SUCCESS;
    }


    /**
     * 修改白名单状态
     *
     * @param requestDTO
     * @return
     */
    @AuthenticateToken
    @PostMapping("/changeStatus")
    public ApiResponse<String> changeStatus(@RequestBody SaveWhitedRuleRequest requestDTO) {
        whitedRuleService.changeStatus(requestDTO.getId(), requestDTO.getEnable());
        return ApiResponse.SUCCESS;
    }

    /**
     * 抢锁
     *
     * @param id
     * @return
     */
    @AuthenticateToken
    @PostMapping("/grabLock/{id}")
    public ApiResponse<String> grabLock(@PathVariable Long id) {
        whitedRuleService.grabLock(id);
        return ApiResponse.SUCCESS;
    }


    /**
     * 获取操作符
     *
     * @return
     * @throws IOException
     */
    @PostMapping("/operator")
    public ApiResponse<List<WhitedRuleOperatorEnum>> operator() throws IOException {
        return new ApiResponse<>(Arrays.asList(WhitedRuleOperatorEnum.values()));
    }


    @PostMapping("/queryExampleData")
    public ApiResponse<WhitedScanInputDataDTO> queryExampleData(@RequestBody QueryWhitedExampleDataRequestDTO requestDTO) {
        if (StringUtils.isBlank(requestDTO.getRiskRuleCode())) {
            return new ApiResponse<>(new WhitedScanInputDataDTO());
        }
        return new ApiResponse<>(whitedRuleService.queryExampleData(requestDTO.getRiskRuleCode()));
    }

    @AuthenticateToken
    @PostMapping("/testRun")
    public ApiResponse<TestRunWhitedRuleResultDTO> testRun(@RequestBody TestRunWhitedRuleRequestDTO dto) {
        TestRunWhitedRuleResultDTO resultDTO = whitedRuleService.testRun(dto);
        return new ApiResponse<>(resultDTO);
    }

    /**
     * 保存白名单
     *
     * @param riskId
     * @return
     * @throws IOException
     */
    @AuthenticateToken
    @PostMapping("/queryWhitedContentByRisk/{riskId}")
    public ApiResponse<SaveWhitedRuleRequest> queryWhitedContentByRisk(@PathVariable Long riskId) throws IOException {
        SaveWhitedRuleRequest saveWhitedRuleRequest = whitedRuleService.queryWhitedContentByRisk(riskId);
        return new ApiResponse<>(saveWhitedRuleRequest);
    }

}

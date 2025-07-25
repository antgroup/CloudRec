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
import com.alipay.application.service.rule.RuleGroupService;
import com.alipay.application.service.rule.job.ScanService;
import com.alipay.application.share.request.rule.RuleGroupRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleGroupVO;
import com.alipay.dao.dto.RuleGroupDTO;
import jakarta.annotation.Resource;
import org.springframework.beans.BeanUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/*
 *@title RuleGroupController
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/5 18:53
 */
@RestController
@RequestMapping("/api/ruleGroup")
@Validated
public class RuleGroupController {

    @Resource
    private RuleGroupService ruleGroupService;

    @Resource
    private ScanService scanService;

    /**
     * Save the risk rule group interface
     */
    @AuthenticateToken
    @PostMapping("/saveRuleGroup")
    public ApiResponse<String> saveRuleGroup(@RequestBody RuleGroupRequest request) {
        RuleGroupDTO ruleGroupDTO = RuleGroupDTO.builder().build();
        BeanUtils.copyProperties(request, ruleGroupDTO);
        return ruleGroupService.saveRuleGroup(ruleGroupDTO);
    }

    /**
     * Trigger rule detection by rule group
     */
    @AuthenticateToken
    @PostMapping("/scanByGroup")
    public ApiResponse<String> scanByGroup(@RequestParam Long id) {
        scanService.scanByGroup(id);
        return ApiResponse.SUCCESS;
    }

    @PostMapping("/queryRuleGroupList")
    public ApiResponse<ListVO<RuleGroupVO>> queryRuleGroupList(@RequestBody RuleGroupRequest request) {
        return ruleGroupService.queryRuleGroupList(request);
    }

    @AuthenticateToken
    @GetMapping("/queryRuleGroupDetail")
    public ApiResponse<RuleGroupVO> queryRuleGroupDetail(@RequestParam Long id) {
        return ruleGroupService.queryRuleGroupDetail(id);
    }

    @AuthenticateToken
    @DeleteMapping("/delRuleGroup")
    public ApiResponse<String> delRuleGroup(@RequestParam Long id) {
        return ruleGroupService.deleteRuleGroup(id);
    }

    @GetMapping("/queryRuleGroupNameList")
    public ApiResponse<List<String>> queryRuleGroupNameList() {
        List<String> ruleGroupNameList = ruleGroupService.queryRuleGroupNameList();
        return new ApiResponse<>(ruleGroupNameList);
    }
}

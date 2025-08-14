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
import com.alipay.application.service.rule.GlobalVariableConfigService;
import com.alipay.application.share.request.admin.ListGlobalVariableConfigRequest;
import com.alipay.application.share.request.admin.SaveGlobalVariableConfigRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.GlobalVariableConfigVO;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.dto.GlobalVariableConfigDTO;
import jakarta.annotation.Resource;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/*
 *@title GlobalVariableConfigController
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/10/21 11:43
 */
@RestController
@RequestMapping("/api/globalVariableConfig")
public class GlobalVariableConfigController {

    @Resource
    private GlobalVariableConfigService globalVariableConfigService;

    /**
     * 保存全局变量配置
     */
    @PostMapping("/saveGlobalVariableConfig")
    @AuthenticateToken
    public ApiResponse<String> saveGlobalVariableConfig(@Validated @RequestBody SaveGlobalVariableConfigRequest req, BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        GlobalVariableConfigDTO globalVariableConfigDTO = GlobalVariableConfigDTO.builder().id(req.getId())
                .name(req.getName())
                .path(req.getPath())
                .data(req.getData())
                .userId(UserInfoContext.getCurrentUser().getUserId())
                .build();
        globalVariableConfigService.saveGlobalVariableConfig(globalVariableConfigDTO);

        return ApiResponse.SUCCESS;
    }

    /**
     * 删除全局变量配置
     */
    @DeleteMapping("/deleteGlobalVariableConfig")
    @AuthenticateToken
    public ApiResponse<String> deleteGlobalVariableConfig(@RequestParam Long id) {
        globalVariableConfigService.deleteGlobalVariableConfig(id);
        return ApiResponse.SUCCESS;
    }

    /**
     * 查询全局变量配置
     */
    @PostMapping("/listGlobalVariableConfig")
    public ApiResponse<ListVO<GlobalVariableConfigVO>> listGlobalVariableConfig(
            @Validated @RequestBody ListGlobalVariableConfigRequest r, BindingResult error) {
        if (error.hasErrors()) {
            return new ApiResponse<>(error);
        }

        GlobalVariableConfigDTO globalVariableConfigDTO = GlobalVariableConfigDTO.builder()
                .name(r.getName())
                .path(r.getPath())
                .data(r.getData())
                .build();
        globalVariableConfigDTO.setPage(r.getPage());
        globalVariableConfigDTO.setSize(r.getSize());
        return globalVariableConfigService.listGlobalVariableConfig(globalVariableConfigDTO);
    }
}

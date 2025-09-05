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
import com.alipay.application.service.common.enums.SubscriptionType;
import com.alipay.application.service.risk.SubscriptionService;
import com.alipay.application.share.request.admin.GetSubscriptionListRequest;
import com.alipay.application.share.request.rule.ChangeStatusRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.risk.SubConfigVO;
import com.alipay.application.share.vo.risk.SubscriptionVO;
import com.alipay.common.enums.Status;
import com.alipay.dao.dto.Subscription;
import com.alipay.dao.dto.SubscriptionDTO;
import jakarta.annotation.Resource;
import org.springframework.beans.BeanUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/*
 * @title RubscriptionController
 *
 * @description
 *
 * @author jietian
 *
 * @version 1.0
 *
 * @create 2024/9/10 16:56
 */
@RestController
@RequestMapping("/api/risk/subscription")
public class SubscriptionController {

    @Resource
    private SubscriptionService subscriptionService;

    /**
     * 获取订阅配置列表
     *
     * @return List<SubConfigVO>
     */
    @GetMapping("/getSubConfigList")
    @AuthenticateToken
    public ApiResponse<List<SubConfigVO>> getSubConfigList() {
        return new ApiResponse<>(subscriptionService.getSubConfigList());
    }

    /**
     * 保存订阅配置
     *
     * @return List<SubConfigVO>
     */
    @AuthenticateToken
    @PostMapping("/saveConfig")
    public ApiResponse<String> saveConfig(@Validated @RequestBody SubscriptionDTO dto, BindingResult results) {
        if (results.hasErrors()) {
            return ApiResponse.FAIL;
        }

        if (dto.getActionList() != null) {
            for (Subscription.Action action : dto.getActionList()) {
                if (action.getActionType() == null || !SubscriptionType.contains(action.getActionType())) {
                    throw new RuntimeException("actionType参数错误");
                }
                if (action.getAction() == null || !SubscriptionType.Action.contains(action.getAction())) {
                    throw new RuntimeException("action参数错误");
                }
            }
        }

        subscriptionService.saveConfig(dto);

        return ApiResponse.SUCCESS;
    }

    /**
     * 获取订阅配置详情
     *
     * @return List<SubConfigVO>
     */
    @GetMapping("/getSubscriptionDetail")
    @AuthenticateToken
    public ApiResponse<SubscriptionVO> getSubscriptionDetail(@RequestParam Long id) {
        return new ApiResponse<>(subscriptionService.getSubscriptionDetail(id));
    }

    /**
     * 获取订阅列表
     *
     * @return List<SubConfigVO>
     */
    @PostMapping("/getSubscriptionList")
    @AuthenticateToken
    public ApiResponse<ListVO<SubscriptionVO>> getSubscriptionList(@RequestBody GetSubscriptionListRequest request) {
        SubscriptionDTO subscriptionDTO = new SubscriptionDTO();
        BeanUtils.copyProperties(request, subscriptionDTO);
        ListVO<SubscriptionVO> listVO = subscriptionService.getSubscriptionList(subscriptionDTO);
        return new ApiResponse<>(listVO);
    }

    /**
     * 获取订阅列表
     *
     * @return List<SubConfigVO>
     */
    @DeleteMapping("/deleteSubscription")
    @AuthenticateToken
    public ApiResponse<String> deleteSubscription(@RequestParam Long id) {
        subscriptionService.deleteSubscription(id);
        return ApiResponse.SUCCESS;
    }

    /**
     * 获取订阅列表
     *
     * @return List<SubConfigVO>
     */
    @PostMapping("/changeStatus")
    @AuthenticateToken
    public ApiResponse<String> changeStatus(@RequestBody @Validated ChangeStatusRequest request, BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }

        Status.exist(request.getStatus());

        subscriptionService.changeStatus(request.getId(), request.getStatus());
        return ApiResponse.SUCCESS;
    }
}

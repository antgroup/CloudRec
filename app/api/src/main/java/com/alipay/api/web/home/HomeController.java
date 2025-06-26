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
package com.alipay.api.web.home;

import com.alipay.api.config.filter.annotation.aop.AuthenticateToken;
import com.alipay.application.service.statistics.Statistics;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.statisics.HomeAggregatedDataVO;
import com.alipay.application.share.vo.statisics.HomePlatformResourceDataVO;
import com.alipay.application.share.vo.statisics.HomeRiskTrendVO;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.dto.HomeTopRiskDTO;
import jakarta.annotation.Resource;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/*
 *@title HomeController
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/10/11 10:17
 */
@RestController
@RequestMapping("/api/home")
@Validated
public class HomeController {

    @Resource
    private Statistics statistics;

    /**
     * Get the current overview data
     *
     * @return ReturnT<AggregatedDataVO>
     */
    @AuthenticateToken
    @PostMapping("/getAggregatedData")
    public ApiResponse<HomeAggregatedDataVO> getAggregatedData() {
        HomeAggregatedDataVO aggregatedData = statistics.getAggregatedData();
        return new ApiResponse<>(aggregatedData);
    }

    /**
     * Obtain the currently supported platforms and displayed resource data
     *
     * @return ReturnT<AggregatedDataVO>
     */
    @AuthenticateToken
    @PostMapping("/getPlatformResourceData")
    public ApiResponse<List<HomePlatformResourceDataVO>> getPlatformResourceData() {
        List<HomePlatformResourceDataVO> platformResourceData = statistics.getPlatformResourceData(UserInfoContext.getCurrentUser().getTenantId());
        return new ApiResponse<>(platformResourceData);
    }

    /**
     *Obtain data on high, medium and low risk pending risks
     *
     * @return ReturnT<AggregatedDataVO>
     */
    @AuthenticateToken
    @PostMapping("/getRiskLevelDataList")
    public ApiResponse<Map<String, Integer>> getRiskLevelDataList() {
        Map<String, Integer> riskLevelDataList = statistics.getRiskLevelDataList(UserInfoContext.getCurrentUser().getTenantId());
        return new ApiResponse<>(riskLevelDataList);
    }

    /**
     * Get the total number of ak, the number of ak with acl, and no acl
     *
     * @return ReturnT<AggregatedDataVO>
     */
    @AuthenticateToken
    @PostMapping("/getAccessKeyAndAclSituation")
    public ApiResponse<List<Map<String, Object>>> getAccessKeyAndAclSituation() {
        List<Map<String, Object>> res = statistics.getAccessKeyAndAclSituation(UserInfoContext.getCurrentUser().getTenantId());
        return new ApiResponse<>(res);
    }

    /**
     * Get the top 10 risk list
     *
     * @return ReturnT<AggregatedDataVO>
     */
    @AuthenticateToken
    @PostMapping("/getTopRiskList")
    public ApiResponse<List<HomeTopRiskDTO>> getTopRiskList() {
        List<HomeTopRiskDTO> topRiskList = statistics.getTopRiskList(UserInfoContext.getCurrentUser().getTenantId());
        return new ApiResponse<>(topRiskList);
    }

    /**
     * Get the risk trends for the last 7 days
     *
     * @return ReturnT<AggregatedDataVO>
     */
    @AuthenticateToken
    @PostMapping("/getRiskTrend")
    public ApiResponse<List<HomeRiskTrendVO>> getRiskTrend() {
        List<HomeRiskTrendVO> riskTrendList = statistics.getRiskTrend(UserInfoContext.getCurrentUser());
        return new ApiResponse<>(riskTrendList);
    }
}

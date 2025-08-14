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
package com.alipay.application.service.common;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alipay.application.service.common.enums.SubscriptionType;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.application.service.risk.RiskStatusManager;
import com.alipay.application.service.risk.engine.Fact;
import com.alipay.application.service.risk.engine.JsonRuleEngine;
import com.alipay.application.share.vo.rule.RuleScanResultVO;
import com.alipay.common.utils.ListUtils;
import com.alipay.dao.dto.RuleGroupDTO;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import com.google.common.collect.Lists;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import jakarta.annotation.Resource;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 *@title Notify
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/10/23 17:14
 */

@Slf4j
@Service
public class Notify {

    public static final int MAX_PUSH_DATA_COUNT = 30;

    @Value("${server.url}")
    private String serverUrl;

    @Resource
    protected RuleScanResultMapper ruleScanResultMapper;

    @Resource
    protected CloudAccountMapper cloudAccountMapper;

    @Resource
    protected RuleMapper ruleMapper;

    @Resource
    protected SubscriptionMapper subscriptionMapper;

    @Resource
    protected SubscriptionActionMapper subscriptionActionMapper;

    @Resource
    protected PlatformMapper platformMapper;

    public void executeNotify(SubscriptionType subscription, SubscriptionType.Action actionType, String url, String title,
                              List<RuleScanResultPO> data) {
        RuleScanResultPO ruleScanResultPO = data.get(0);
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(ruleScanResultPO.getCloudAccountId());
        if (cloudAccountPO == null) {
            log.error("Cloud Account {} no longer exists", ruleScanResultPO.getCloudAccountId());
            return;
        }
        PlatformPO platformPO = platformMapper.findByPlatform(cloudAccountPO.getPlatform());
        if (platformPO == null) {
            log.error("Cloud Platform {} no longer exists", cloudAccountPO.getPlatform());
            return;
        }
        RulePO rulePO = ruleMapper.selectByPrimaryKey(ruleScanResultPO.getRuleId());
        if (rulePO == null) {
            log.error("Rule {} no longer exists", ruleScanResultPO.getRuleId());
            return;
        }

        // Template analysis
        List<String> itemList = new ArrayList<>();
        for (RuleScanResultPO d : data) {
            String context = parseTemplate(rulePO.getContext(), d.getResult());
            itemList.add(context);
        }

        // Build notification text
        NotifyText.NotifyTextBuilder builder = NotifyText.NotifyTextBuilder
                .builder(serverUrl)
                .ruleName(rulePO.getPlatform(), rulePO.getRuleName(), rulePO.getRuleCode())
                .baseInfo(platformPO.getPlatformName(), cloudAccountPO.getCloudAccountId(), cloudAccountPO.getAlias(), data.size())
                .ruleDesc(rulePO.getRuleDesc()).advice(rulePO.getAdvice()).link(rulePO.getLink()).context(itemList, platformPO.getPlatform(), rulePO.getRuleName())
                .end();

        if (subscription.name().equals(SubscriptionType.realtime.name())) {
            // Query the number of existing risks
            List<RuleScanResultPO> ruleScanResult = getRuleScanResult(rulePO.getId(), cloudAccountPO.getCloudAccountId());
            builder.baseInfo(platformPO.getPlatformName(), cloudAccountPO.getCloudAccountId(), cloudAccountPO.getAlias(), ruleScanResult.size(), data.size());
        }

        NotifyText.notify(actionType.name(), url, title, builder.build().toString());
    }

    public List<RuleScanResultPO> getRuleScanResult(Long ruleId, String cloudAccountId) {
        RuleScanResultDTO ruleScanResultDTO = RuleScanResultDTO.builder()
                .status(RiskStatusManager.RiskStatus.UNREPAIRED.name()).ruleId(ruleId).cloudAccountIdList(List.of(cloudAccountId))
                .build();

        return ruleScanResultMapper.findList(ruleScanResultDTO);
    }


    // Define regular expressions
    private static final String regex = "\\{\\s*([^{}]+)\\s*\\}";

    /**
     * 解析模板：
     * <p>
     *
     * @param contextTemplate 模板 eg: 安全组id {$.d.groupId},规则描述 {$.d.description},存在安全风险
     * @param jsonString      json字符串 eg: {"d":{"groupId":"sg-12345678","description":"安全组描述"}}
     * @return 解析后的字符串 eg: 安全组id sg-12345678,规则描述 安全组描述,存在安全风险
     */
    public static String parseTemplate(String contextTemplate, String jsonString) {
        if (StringUtils.isEmpty(contextTemplate)) {
            return jsonString;
        }
        if (StringUtils.isEmpty(jsonString)) {
            return null;
        }
        log.info("parseTemplate contextTemplate: {}, jsonString: {}", contextTemplate, jsonString);
        Object document = Configuration.defaultConfiguration().jsonProvider().parse(jsonString);

        String result = contextTemplate;
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(contextTemplate);

        while (matcher.find()) {
            String key = matcher.group(1);
            Object object = null;
            try {
                object = JsonPath.read(document, key);
            } catch (PathNotFoundException e) {
                log.error("No path found: {}", key);
            }
            String value = object != null ? object.toString() : "N/A";
            result = result.replace("{" + key + "}", value);
        }

        if (result.equals(contextTemplate)) {
            return null;
        }

        return result;
    }

    /**
     * Push risk data
     *
     * @param uri  Interface address
     * @param data Risk data
     */
    public void interfaceCallBack(String uri, List<RuleScanResultPO> data) {
        List<RuleScanResultVO> collect = data.stream().map(RuleScanResultVO::buildList).toList();
        // A maximum of 30 items can be submitted at a time
        List<List<RuleScanResultVO>> partition = Lists.partition(collect, MAX_PUSH_DATA_COUNT);
        for (List<RuleScanResultVO> list : partition) {
            String scanResult = JSON.toJSONString(list, SerializerFeature.WriteMapNullValue);
            try {
                URL url = new URL(uri);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", "application/json; utf-8");
                connection.setRequestProperty("Accept", "application/json");
                connection.setDoOutput(true);

                Map<String, Object> param = new HashMap<>();
                param.put("scanResult", scanResult);
                try (OutputStream os = connection.getOutputStream()) {
                    byte[] input = JSON.toJSONString(param).getBytes(StandardCharsets.UTF_8);
                    os.write(input, 0, input.length);
                }


                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder response = new StringBuilder();
                    String responseLine;
                    while ((responseLine = br.readLine()) != null) {
                        response.append(responseLine.trim());
                    }
                    log.info("Interface callback response: {}", response);
                }

            } catch (Exception e) {
                log.error("Interface callback failed", e);
            }
        }
    }

    /**
     * Filter Risk
     *
     * @param data           Risk data JSON
     * @param filterParam    Filter parameters
     * @param ruleConfigJson Rules configuration json
     * @return Filtered risk list
     */
    public List<RuleScanResultPO> filterList(List<RuleScanResultPO> data, FilterParam filterParam,
                                             String ruleConfigJson) {
        List<RuleScanResultPO> result = new ArrayList<>();
        if (data == null || data.isEmpty()) {
            return result;
        }

        for (RuleScanResultPO d : data) {
            boolean match = Objects.requireNonNull(JsonRuleEngine.parseOne(ruleConfigJson))
                    .match(Arrays.asList(new Fact(SubscriptionConfigType.cloudAccountId.getKey(), filterParam.getCloudAccountId()),
                            new Fact(SubscriptionConfigType.ruleId.getKey(), filterParam.getRuleId()),
                            new Fact(SubscriptionConfigType.tenantId.getKey(), filterParam.getTenantId()),
                            new Fact(SubscriptionConfigType.ruleGroupId.getKey(), filterParam.getRuleGroupIdList()),
                            new Fact(SubscriptionConfigType.platform.getKey(), filterParam.getPlatform())));

            if (match) {
                result.add(d);
            }
        }

        if (result.isEmpty()) {
            log.info("ruleId {} cloudAccountId {} The rule scan result is empty and execution is skipped.", filterParam.getRuleId(),
                    filterParam.getCloudAccountId());
        }

        return result;
    }

    @Getter
    @Setter
    @Builder
    public static class FilterParam {
        private String cloudAccountId;
        private Long ruleId;
        private Long tenantId;
        private List<Long> ruleGroupIdList;
        private String platform;


        public static FilterParam buildParam(RulePO rulePO, CloudAccountPO cloudAccountPO) {
            FilterParamBuilder builder = FilterParam.builder()
                    .ruleId(rulePO.getId())
                    .tenantId(cloudAccountPO.getTenantId())
                    .cloudAccountId(cloudAccountPO.getCloudAccountId())
                    .platform(cloudAccountPO.getPlatform());


            RuleGroupMapper ruleGroupMapper = SpringUtils.getBean(RuleGroupMapper.class);
            List<RuleGroupPO> list = ruleGroupMapper.findList(RuleGroupDTO.builder().ruleIdList(List.of(rulePO.getId())).build());
            if (ListUtils.isNotEmpty(list)) {
                builder.ruleGroupIdList(list.stream().map(RuleGroupPO::getId).toList());
            }

            return builder.build();
        }
    }
}

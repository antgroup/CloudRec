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

import com.alipay.application.service.common.enums.SubscriptionType;
import com.dingtalk.api.DefaultDingTalkClient;
import com.dingtalk.api.DingTalkClient;
import com.dingtalk.api.request.OapiRobotSendRequest;
import com.dingtalk.api.response.OapiRobotSendResponse;
import com.taobao.api.ApiException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.StringEntity;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;

/*
 *@title NotifyTextBuilder
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/10/23 14:46
 */
@Getter
@Setter
@Slf4j
public class NotifyText {

    /**
     * 规则名称
     */
    private String ruleName;

    /**
     *
     */
    private String ruleCode;

    /**
     * 基础信息
     */
    private String baseInfo;

    /**
     * 规则描述
     */
    private String ruleDesc;

    /**
     * 上下文信息
     */
    private String context;

    /**
     * 修复建议
     */
    private String advice;

    /**
     * 链接
     */
    private String link;

    /**
     * end
     */
    private String end;

    public static class NotifyTextBuilder {

        /**
         * 风险上下文限制条数
         */
        private static final int contextCount = 5;

        /**
         * 通知文本
         */
        private final NotifyText notifyText;

        /**
         * 服务器地址
         */
        private final String serverUrl;

        private NotifyTextBuilder(String serverUrl) {
            this.notifyText = new NotifyText();
            this.serverUrl = serverUrl;
        }

        public static NotifyTextBuilder builder(String serverUrl) {
            return new NotifyTextBuilder(serverUrl);
        }

        /**
         * 设置规则名称
         *
         * @param platform 平台
         * @param ruleName 规则名称
         * @param ruleCode rule code
         * @return NotifyTextBuilder
         */
        public NotifyTextBuilder ruleName(String platform, String ruleName, String ruleCode) {
            String safeRuleCode = ruleCode.replaceAll(" ", "%20");
            String name = String.format("""
                    ## [%s](%s/riskManagement/riskList?platform=%s&ruleCode=%s)
                    
                    ---------------------------------------------
                    
                    """, ruleName, this.serverUrl, platform, safeRuleCode);
            notifyText.setRuleName(name);
            return this;
        }

        /**
         * 设置基础信息
         *
         * @param platform             平台
         * @param cloudAccountId       云账号ID
         * @param alies                云账号别名
         * @param stockRiskCount       存量风险数
         * @param IncrementalRiskCount 增量风险数
         * @return NotifyTextBuilder
         */
        public NotifyTextBuilder baseInfo(String platform, String cloudAccountId, String alies, Integer stockRiskCount,
                                          Integer IncrementalRiskCount) {
            String baseInfo = String.format("""
                    
                    ### 基础信息
                    云平台：%s
                    
                    云账号：%s
                    
                    云账号别名：%s
                    
                    存量风险：**%s**
                    
                    本次增量：**%s**
                    
                    ---------------------------------------------
                    
                    """, platform, cloudAccountId, alies, stockRiskCount, IncrementalRiskCount);
            notifyText.setBaseInfo(baseInfo);
            return this;
        }

        /**
         * 设置基础信息
         *
         * @param platform       平台
         * @param cloudAccountId 云账号ID
         * @param alies          云账号别名
         * @param stockRiskCount 存量风险数
         * @return NotifyTextBuilder
         */
        public NotifyTextBuilder baseInfo(String platform, String cloudAccountId, String alies,
                                          Integer stockRiskCount) {
            String baseInfo = String.format("""
                    
                    ### 基础信息
                    云平台：%s
                    
                    云账号：%s
                    
                    云账号别名：%s
                    
                    存量风险：**%s**
                    
                    ---------------------------------------------
                    
                    """, platform, cloudAccountId, alies, stockRiskCount);
            notifyText.setBaseInfo(baseInfo);
            return this;
        }

        /**
         * 设置风险描述
         *
         * @param ruleDesc 风险描述
         * @return NotifyTextBuilder
         */
        public NotifyTextBuilder ruleDesc(String ruleDesc) {
            if (ruleDesc == null) {
                return this;
            }
            ruleDesc = String.format("""
                    
                    ### 风险描述
                    %s
                    
                    ---------------------------------------------
                    
                    """, ruleDesc);
            notifyText.setRuleDesc(ruleDesc);
            return this;
        }

        /**
         * 设置风险描述
         *
         * @param itemList 风险的上下文列表
         * @return NotifyTextBuilder
         */
        public NotifyTextBuilder context(List<String> itemList, String platform, String ruleName) {
            ruleName = ruleName.replaceAll(" ", "%20");
            StringBuilder contenxt = new StringBuilder();
            int count = 0;
            for (int i = 0; i < itemList.size(); i++) {
                if (StringUtils.isBlank(itemList.get(0))) {
                    continue;
                }
                if (count < contextCount) {
                    contenxt.append(i + 1).append(". ").append(String.format("""
                            %s
                            
                            """, itemList.get(i)));
                    count++;
                }
            }

            // 未配置模板的情况不展示告警上下文
            if (StringUtils.isBlank(contenxt.toString())) {
                return this;
            }

            contenxt = new StringBuilder(String.format("""
                    
                    ### 上下文
                    
                    %s
                    
                    """, contenxt));

            if (itemList.size() > contextCount) {
                String end = String.format("##### [省略%s条，点击查看更多](%s/riskManagement/riskList?platform=%s&ruleName=%s)",
                        itemList.size() - contextCount, this.serverUrl, platform, ruleName);
                contenxt.append(end);
            }

            contenxt.append("\n---------------------------------------------\n");
            notifyText.setContext(contenxt.toString());
            return this;
        }

        /**
         * 设置解决方案
         *
         * @param advice 解决方案
         * @return NotifyTextBuilder
         */
        public NotifyTextBuilder advice(String advice) {
            if (advice == null) {
                return this;
            }
            advice = String.format("""
                    
                    ### 解决方案
                    %s
                    
                    ---------------------------------------------
                    
                    """, advice);
            notifyText.setAdvice(advice);
            return this;
        }

        /**
         * 设置链接
         *
         * @param link 链接
         * @return NotifyTextBuilder
         */
        public NotifyTextBuilder link(String link) {
            if (link == null) {
                return this;
            }
            link = String.format("""
                    ### 参考链接
                    
                    %s
                    
                    ---------------------------------------------
                    
                    """, link);
            notifyText.setLink(link);
            return this;
        }

        public NotifyTextBuilder end() {
            notifyText.setEnd("> 来自CloudRec订阅服务");
            return this;
        }

        /**
         * 构建通知
         *
         * @return notifyText
         */
        public NotifyText build() {
            return notifyText;
        }
    }

    public String toString() {
        String result = "";
        if (this.getRuleName() != null) {
            result += this.getRuleName();
        }
        if (this.getBaseInfo() != null) {
            result += this.getBaseInfo();
        }
        if (this.getRuleDesc() != null) {
            result += this.getRuleDesc();
        }
        if (this.getContext() != null) {
            result += this.getContext();
        }
        if (this.getAdvice() != null) {
            result += this.getAdvice();
        }
        if (this.getLink() != null) {
            result += this.getLink();
        }
        if (this.getEnd() != null) {
            result += this.getEnd();
        }

        return result;
    }

    public static void notify(String type, String url, String title, String text) {
        log.info("Start alerting title: {} type: {}", title, type);
        if (SubscriptionType.Action.dingGroup.name().equals(type)) {
            log.info("Start DingTalk Group Alert notifyText: {}", text);
            sendDingMessage(url, title, text);
        }

        if (SubscriptionType.Action.wechat.name().equals(type)) {
            text = text.replaceAll("---------------------------------------------", "");
            log.info("Start an alert from the WeChat group of enterprises notifyText: {}", text);
            sendWeChatMessage(url, text);
        }
        log.info("Complete the alarm title: {} type: {}", title, type);
    }

    /**
     * 标题语法
     */
    private static void sendDingMessage(String url, String title, String text) {
        DingTalkClient client = new DefaultDingTalkClient(url);

        try {
            OapiRobotSendRequest request = new OapiRobotSendRequest();
            request.setMsgtype("markdown");
            OapiRobotSendRequest.Markdown markdown = new OapiRobotSendRequest.Markdown();
            markdown.setTitle(title);
            markdown.setText(text);
            request.setMarkdown(markdown);
            OapiRobotSendRequest.At at = new OapiRobotSendRequest.At();
            at.setIsAtAll(false);
            request.setAt(at);
            OapiRobotSendResponse response = client.execute(request);
            if (!response.isSuccess()) {
                log.error("DingTalk alarm sending result:{}", response.getErrmsg());
            } else {
                log.info("DingTalk alarm was sent successfully:{}", response.getMessage());
            }

        } catch (ApiException e) {
            log.error("DingTalk alarm sending exception:{}", e.getMessage(), e);
        }
    }

    // 发送消息的方法
    public static void sendWeChatMessage(String webhookUrl, String message) {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost post = new HttpPost(webhookUrl);
        String jsonPayload = String.format("{\"msgtype\": \"markdown\", \"markdown\": {\"content\": \"%s\"}}",
                message.replace("\"", "\\\""));

        try {
            // 创建消息体
            StringEntity entity = new StringEntity(jsonPayload);
            post.setEntity(entity);
            post.setHeader("Content-type", "application/json");
            // 设置字符集 utf-8
            post.setEntity(new StringEntity(jsonPayload));

            // 发送请求并处理响应
            try (CloseableHttpResponse response = client.execute(post)) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
                String line;
                while ((line = reader.readLine()) != null) {
                    log.info("Enterprise WeChat alert sending results:{}", line);
                }
            }
        } catch (Exception e) {
            log.error("Enterprise WeChat alert send failed", e);
        }
    }
}

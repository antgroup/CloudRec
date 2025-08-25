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
package com.alipay.application.service.risk.engine;

import com.alipay.application.service.rule.WhitedRuleEngineMatcher;
import com.alipay.application.share.request.rule.WhitedRuleConfigDTO;
import com.alipay.common.enums.WhitedRuleOperatorEnum;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end tests for WhitedRuleEngineMatcher
 * Tests the complete rule engine matching functionality
 */
class WhitedRuleEngineMatcherTest {

    private WhitedRuleEngineMatcher matcher;
    private Map<String, String> testRiskData;

    @BeforeEach
    void setUp() {
        matcher = new WhitedRuleEngineMatcher();
        testRiskData = new HashMap<>();
        testRiskData.put("userId", "12345");
        testRiskData.put("userType", "premium");
        testRiskData.put("accountStatus", "active");
        testRiskData.put("riskScore", "75");
        testRiskData.put("country", "US");
        testRiskData.put("isVip", "true");
        testRiskData.put("transactionAmount", "1000.50");
    }

    /**
     * Test simple single condition matching
     */
    @Test
    void testSimpleSingleConditionMatching() {
        // Create a simple rule configuration
        WhitedRuleConfigDTO rule = new WhitedRuleConfigDTO();
        rule.setKey("userType");
        rule.setOperator(WhitedRuleOperatorEnum.EQ);
        rule.setValue("premium");
        
        assertTrue(matcher.matchRule(rule, testRiskData));
        
        // Test non-matching condition
        WhitedRuleConfigDTO nonMatchingRule = new WhitedRuleConfigDTO();
        nonMatchingRule.setKey("userType");
        nonMatchingRule.setOperator(WhitedRuleOperatorEnum.EQ);
        nonMatchingRule.setValue("basic");
        
        assertFalse(matcher.matchRule(nonMatchingRule, testRiskData));
    }

    /**
     * Test multiple conditions with AND logic
     */
    @Test
    void testMultipleConditionsWithAndLogic() {
        // Create multiple rules that should all match - using resourceSnapshoot field
        List<WhitedRuleConfigDTO> rules = Arrays.asList(
            createRuleWithId(1, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "premium"),
            createRuleWithId(2, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "active"),
            createRuleWithId(3, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "true")
        );
        
        // Use AND condition: all rules must match
        assertTrue(matcher.matchWhitelistRule(rules, "1 AND 2 AND 3", createRuleScanResult()));
        
        // Test with one non-matching condition
        List<WhitedRuleConfigDTO> mixedRules = Arrays.asList(
            createRuleWithId(1, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "premium"),
            createRuleWithId(2, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "inactive"), // This won't match
            createRuleWithId(3, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "true")
        );
        
        assertFalse(matcher.matchWhitelistRule(mixedRules, "1 AND 2 AND 3", createRuleScanResult()));
    }
    
    private WhitedRuleConfigDTO createRule(String key, WhitedRuleOperatorEnum operator, String value) {
        WhitedRuleConfigDTO rule = new WhitedRuleConfigDTO();
        rule.setKey(key);
        rule.setOperator(operator);
        rule.setValue(value);
        return rule;
    }
    
    private WhitedRuleConfigDTO createRuleWithId(Integer id, String key, WhitedRuleOperatorEnum operator, String value) {
        WhitedRuleConfigDTO rule = new WhitedRuleConfigDTO();
        rule.setId(id);
        rule.setKey(key);
        rule.setOperator(operator);
        rule.setValue(value);
        return rule;
    }
    
    private com.alipay.dao.po.RuleScanResultPO createRuleScanResult() {
        com.alipay.dao.po.RuleScanResultPO result = new com.alipay.dao.po.RuleScanResultPO();
        result.setId(1L);
        result.setRuleId(100L);
        result.setCloudAccountId("test-account");
        result.setResourceId("test-resource");
        result.setResourceName("Test Resource");
        result.setPlatform("AWS");
        result.setResourceType("EC2");
        result.setRegion("us-east-1");
        result.setTenantId(1L);
        result.setVersion(1L);
        result.setStatus("UNREPAIRED");
        result.setResourceStatus("RUNNING");
        
        // Create a JSON representation of the test risk data for resource snapshot
        StringBuilder resourceSnapshot = new StringBuilder("{");
        testRiskData.forEach((key, value) -> {
            resourceSnapshot.append("\"").append(key).append("\":\"").append(value).append("\",");
        });
        if (resourceSnapshot.length() > 1) {
            resourceSnapshot.setLength(resourceSnapshot.length() - 1); // Remove last comma
        }
        resourceSnapshot.append("}");
        result.setResourceSnapshoot(resourceSnapshot.toString());
        
        return result;
    }

    /**
     * Test LIKE operator in rule engine
     */
    @Test
    void testLikeOperatorInRuleEngine() {
        WhitedRuleConfigDTO likeRule = new WhitedRuleConfigDTO();
        likeRule.setKey("userId");
        likeRule.setOperator(WhitedRuleOperatorEnum.LIKE);
        likeRule.setValue("123");
        
        assertTrue(matcher.matchRule(likeRule, testRiskData));
        
        // Test non-matching LIKE
        WhitedRuleConfigDTO nonMatchingLikeRule = new WhitedRuleConfigDTO();
        nonMatchingLikeRule.setKey("userId");
        nonMatchingLikeRule.setOperator(WhitedRuleOperatorEnum.LIKE);
        nonMatchingLikeRule.setValue("999");
        
        assertFalse(matcher.matchRule(nonMatchingLikeRule, testRiskData));
    }

    /**
     * Test IN operator in rule engine
     */
    @Test
    void testInOperatorInRuleEngine() {
        WhitedRuleConfigDTO inRule = new WhitedRuleConfigDTO();
        inRule.setKey("country");
        inRule.setOperator(WhitedRuleOperatorEnum.IN);
        inRule.setValue("US,CA,UK");
        
        assertTrue(matcher.matchRule(inRule, testRiskData));
        
        // Test non-matching IN
        WhitedRuleConfigDTO nonMatchingInRule = new WhitedRuleConfigDTO();
        nonMatchingInRule.setKey("country");
        nonMatchingInRule.setOperator(WhitedRuleOperatorEnum.IN);
        nonMatchingInRule.setValue("FR,DE,IT");
        
        assertFalse(matcher.matchRule(nonMatchingInRule, testRiskData));
    }

    /**
     * Test NOT_IN operator in rule engine
     */
    @Test
    void testNotInOperatorInRuleEngine() {
        WhitedRuleConfigDTO notInRule = new WhitedRuleConfigDTO();
        notInRule.setKey("country");
        notInRule.setOperator(WhitedRuleOperatorEnum.NOT_IN);
        notInRule.setValue("FR,DE,IT");
        
        assertTrue(matcher.matchRule(notInRule, testRiskData));
        
        // Test matching NOT_IN (should return false)
        WhitedRuleConfigDTO matchingNotInRule = new WhitedRuleConfigDTO();
        matchingNotInRule.setKey("country");
        matchingNotInRule.setOperator(WhitedRuleOperatorEnum.NOT_IN);
        matchingNotInRule.setValue("US,CA,UK");
        
        assertFalse(matcher.matchRule(matchingNotInRule, testRiskData));
    }

    /**
     * Test numeric value matching
     */
    @Test
    void testNumericValueMatching() {
        WhitedRuleConfigDTO numericRule = new WhitedRuleConfigDTO();
        numericRule.setKey("riskScore");
        numericRule.setOperator(WhitedRuleOperatorEnum.EQ);
        numericRule.setValue("75");
        
        assertTrue(matcher.matchRule(numericRule, testRiskData));
        
        // Test numeric NE
        WhitedRuleConfigDTO numericNeRule = new WhitedRuleConfigDTO();
        numericNeRule.setKey("riskScore");
        numericNeRule.setOperator(WhitedRuleOperatorEnum.NE);
        numericNeRule.setValue("100");
        
        assertTrue(matcher.matchRule(numericNeRule, testRiskData));
    }

    /**
     * Test decimal value matching
     */
    @Test
    void testDecimalValueMatching() {
        WhitedRuleConfigDTO decimalRule = new WhitedRuleConfigDTO();
        decimalRule.setKey("transactionAmount");
        decimalRule.setOperator(WhitedRuleOperatorEnum.EQ);
        decimalRule.setValue("1000.50");
        
        assertTrue(matcher.matchRule(decimalRule, testRiskData));
    }

    /**
     * Test boolean value matching
     */
    @Test
    void testBooleanValueMatching() {
        WhitedRuleConfigDTO booleanRule = new WhitedRuleConfigDTO();
        booleanRule.setKey("isVip");
        booleanRule.setOperator(WhitedRuleOperatorEnum.EQ);
        booleanRule.setValue("true");
        
        assertTrue(matcher.matchRule(booleanRule, testRiskData));
        
        // Test boolean NE
        WhitedRuleConfigDTO booleanNeRule = new WhitedRuleConfigDTO();
        booleanNeRule.setKey("isVip");
        booleanNeRule.setOperator(WhitedRuleOperatorEnum.NE);
        booleanNeRule.setValue("false");
        
        assertTrue(matcher.matchRule(booleanNeRule, testRiskData));
    }

    /**
     * Test complex rule with multiple operators
     */
    @Test
    void testComplexRuleWithMultipleOperators() {
        List<WhitedRuleConfigDTO> complexRules = Arrays.asList(
            createRuleWithId(1, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "premium"),
            createRuleWithId(2, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "active"),
            createRuleWithId(3, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "US"),
            createRuleWithId(4, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "123"),
            createRuleWithId(5, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "true")
        );
        
        assertTrue(matcher.matchWhitelistRule(complexRules, "1&&2&&3&&4&&5", createRuleScanResult()));
    }

    /**
     * Test with empty condition items
     */
    @Test
    void testEmptyConditionItems() {
        List<WhitedRuleConfigDTO> emptyRules = Collections.emptyList();
        
        assertTrue(matcher.matchWhitelistRule(emptyRules, "", createRuleScanResult())); // Empty conditions should match
    }

    /**
     * Test with null condition
     */
    @Test
    void testNullCondition() {
        assertFalse(matcher.matchWhitelistRule(null, "", createRuleScanResult()));
    }

    /**
     * Test with null facts
     */
    @Test
    void testNullFacts() {
        WhitedRuleConfigDTO rule = createRule("userType", WhitedRuleOperatorEnum.EQ, "premium");
        
        assertFalse(matcher.matchRule(rule, null));
    }

    /**
     * Test with empty facts list
     */
    @Test
    void testEmptyFactsList() {
        WhitedRuleConfigDTO rule = createRule("userType", WhitedRuleOperatorEnum.EQ, "premium");
        
        assertFalse(matcher.matchRule(rule, Collections.emptyMap()));
    }

    /**
     * Test rule engine performance with complex conditions
     */
    @Test
    void testRuleEnginePerformance() {
        // Create a complex condition with multiple items
        List<WhitedRuleConfigDTO> performanceRules = Arrays.asList(
            createRuleWithId(1, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "premium"),
            createRuleWithId(2, "resourceSnapshoot", WhitedRuleOperatorEnum.NOT_LIKE, "suspended"),
            createRuleWithId(3, "resourceSnapshoot", WhitedRuleOperatorEnum.NOT_LIKE, "RESTRICTED"),
            createRuleWithId(4, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "75"),
            createRuleWithId(5, "resourceSnapshoot", WhitedRuleOperatorEnum.LIKE, "true")
        );
        
        long startTime = System.currentTimeMillis();
        boolean result = matcher.matchWhitelistRule(performanceRules, "1&&2&&3&&4&&5", createRuleScanResult());
        long endTime = System.currentTimeMillis();
        
        assertTrue(result);
        assertTrue((endTime - startTime) < 50); // Should complete within 50ms
    }

    /**
     * Test rule engine with facts containing null values
     */
    @Test
    void testRuleEngineWithNullFactValues() {
        Map<String, String> dataWithNull = new HashMap<>();
        dataWithNull.put("userId", "12345");
        dataWithNull.put("userType", null);
        dataWithNull.put("accountStatus", "active");
        dataWithNull.put("riskScore", "75");
        
        // Test EQ with null
        WhitedRuleConfigDTO nullRule = createRule("userType", WhitedRuleOperatorEnum.EQ, null);
        
        assertTrue(matcher.matchRule(nullRule, dataWithNull));
        
        // Test NE with null
        WhitedRuleConfigDTO notNullRule = createRule("userType", WhitedRuleOperatorEnum.NE, "premium");
        
        assertTrue(matcher.matchRule(notNullRule, dataWithNull));
    }
}
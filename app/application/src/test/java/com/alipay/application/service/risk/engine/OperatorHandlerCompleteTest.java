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

import com.alipay.application.service.risk.engine.handler.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for OperatorHandlerComplete
 * Tests the complete operator handler system with all supported operators
 */
class OperatorHandlerCompleteTest {

    private OperatorHandlerComplete operatorHandlerComplete;
    private List<Fact> testFacts;

    @BeforeEach
    void setUp() {
        operatorHandlerComplete = new OperatorHandlerComplete();
        testFacts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("priority", 3),
            new Fact("name", "test user"),
            new Fact("enabled", true),
            new Fact("category", "premium")
        );
    }

    /**
     * Test EQ operator integration
     */
    @Test
    void testEqOperatorIntegration() {
        ConditionItem condition = new ConditionItem(Operator.EQ, "status", "active");
        assertTrue(operatorHandlerComplete.handle(condition, testFacts));
        
        condition = new ConditionItem(Operator.EQ, "status", "inactive");
        assertFalse(operatorHandlerComplete.handle(condition, testFacts));
    }

    /**
     * Test NE operator integration
     */
    @Test
    void testNeOperatorIntegration() {
        ConditionItem condition = new ConditionItem(Operator.NE, "status", "inactive");
        assertTrue(operatorHandlerComplete.handle(condition, testFacts));
        
        condition = new ConditionItem(Operator.NE, "status", "active");
        assertFalse(operatorHandlerComplete.handle(condition, testFacts));
    }

    /**
     * Test LIKE operator integration
     */
    @Test
    void testLikeOperatorIntegration() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "name", "test");
        assertTrue(operatorHandlerComplete.handle(condition, testFacts));
        
        condition = new ConditionItem(Operator.LIKE, "name", "admin");
        assertFalse(operatorHandlerComplete.handle(condition, testFacts));
    }

    /**
     * Test NOT_LIKE operator integration
     */
    @Test
    void testNotLikeOperatorIntegration() {
        ConditionItem condition = new ConditionItem(Operator.NOT_LIKE, "name", "admin");
        assertTrue(operatorHandlerComplete.handle(condition, testFacts));
        
        condition = new ConditionItem(Operator.NOT_LIKE, "name", "test");
        assertFalse(operatorHandlerComplete.handle(condition, testFacts));
    }

    /**
     * Test IN operator integration
     */
    @Test
    void testInOperatorIntegration() {
        ConditionItem condition = new ConditionItem(Operator.IN, "status", Arrays.asList("active", "pending", "inactive"));
        assertTrue(operatorHandlerComplete.handle(condition, testFacts));
        
        condition = new ConditionItem(Operator.IN, "status", Arrays.asList("pending", "inactive", "deleted"));
        assertFalse(operatorHandlerComplete.handle(condition, testFacts));
    }

    /**
     * Test NOT_IN operator integration
     */
    @Test
    void testNotInOperatorIntegration() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "status", Arrays.asList("pending", "inactive", "deleted"));
        assertTrue(operatorHandlerComplete.handle(condition, testFacts));
        
        condition = new ConditionItem(Operator.NOT_IN, "status", Arrays.asList("active", "pending", "inactive"));
        assertFalse(operatorHandlerComplete.handle(condition, testFacts));
    }

    /**
     * Test multiple conditions with different operators
     */
    @Test
    void testMultipleConditionsWithDifferentOperators() {
        // Test EQ and IN combination
        ConditionItem eqCondition = new ConditionItem(Operator.EQ, "status", "active");
        ConditionItem inCondition = new ConditionItem(Operator.IN, "priority", Arrays.asList(1, 2, 3, 4, 5));
        
        assertTrue(operatorHandlerComplete.handle(eqCondition, testFacts));
        assertTrue(operatorHandlerComplete.handle(inCondition, testFacts));
        
        // Test NE and LIKE combination
        ConditionItem neCondition = new ConditionItem(Operator.NE, "category", "basic");
        ConditionItem likeCondition = new ConditionItem(Operator.LIKE, "name", "user");
        
        assertTrue(operatorHandlerComplete.handle(neCondition, testFacts));
        assertTrue(operatorHandlerComplete.handle(likeCondition, testFacts));
    }

    /**
     * Test with different data types
     */
    @Test
    void testDifferentDataTypes() {
        // String
        ConditionItem stringCondition = new ConditionItem(Operator.EQ, "status", "active");
        assertTrue(operatorHandlerComplete.handle(stringCondition, testFacts));
        
        // Integer
        ConditionItem intCondition = new ConditionItem(Operator.EQ, "priority", 3);
        assertTrue(operatorHandlerComplete.handle(intCondition, testFacts));
        
        // Boolean
        ConditionItem boolCondition = new ConditionItem(Operator.EQ, "enabled", true);
        assertTrue(operatorHandlerComplete.handle(boolCondition, testFacts));
    }

    /**
     * Test with null values
     */
    @Test
    void testNullValues() {
        List<Fact> factsWithNull = Arrays.asList(
            new Fact("status", null),
            new Fact("priority", 3),
            new Fact("name", "test")
        );
        
        ConditionItem nullCondition = new ConditionItem(Operator.EQ, "status", null);
        assertTrue(operatorHandlerComplete.handle(nullCondition, factsWithNull));
        
        ConditionItem notNullCondition = new ConditionItem(Operator.NE, "status", null);
        assertFalse(operatorHandlerComplete.handle(notNullCondition, factsWithNull));
    }

    /**
     * Test with empty facts list
     */
    @Test
    void testEmptyFactsList() {
        ConditionItem condition = new ConditionItem(Operator.EQ, "status", "active");
        assertFalse(operatorHandlerComplete.handle(condition, Collections.emptyList()));
    }

    /**
     * Test with non-existent fact key
     */
    @Test
    void testNonExistentFactKey() {
        ConditionItem condition = new ConditionItem(Operator.EQ, "nonexistent", "value");
        assertFalse(operatorHandlerComplete.handle(condition, testFacts));
    }

    /**
     * Test that all operators are supported by trying each one
     */
    @Test
    void testAllOperatorsSupported() {
        // Test that all operators work without throwing exceptions
        ConditionItem eqCondition = new ConditionItem(Operator.EQ, "status", "active");
        ConditionItem neCondition = new ConditionItem(Operator.NE, "status", "inactive");
        ConditionItem likeCondition = new ConditionItem(Operator.LIKE, "name", "test");
        ConditionItem notLikeCondition = new ConditionItem(Operator.NOT_LIKE, "name", "admin");
        ConditionItem inCondition = new ConditionItem(Operator.IN, "status", Arrays.asList("active", "pending"));
        ConditionItem notInCondition = new ConditionItem(Operator.NOT_IN, "status", Arrays.asList("deleted", "archived"));
        
        // All should execute without throwing exceptions
        assertDoesNotThrow(() -> operatorHandlerComplete.handle(eqCondition, testFacts));
        assertDoesNotThrow(() -> operatorHandlerComplete.handle(neCondition, testFacts));
        assertDoesNotThrow(() -> operatorHandlerComplete.handle(likeCondition, testFacts));
        assertDoesNotThrow(() -> operatorHandlerComplete.handle(notLikeCondition, testFacts));
        assertDoesNotThrow(() -> operatorHandlerComplete.handle(inCondition, testFacts));
        assertDoesNotThrow(() -> operatorHandlerComplete.handle(notInCondition, testFacts));
    }

    /**
     * Test complex scenario with multiple facts of same key
     */
    @Test
    void testComplexScenarioWithMultipleSameKeyFacts() {
        List<Fact> complexFacts = Arrays.asList(
            new Fact("tag", "important"),
            new Fact("tag", "urgent"),
            new Fact("tag", "review"),
            new Fact("priority", 1),
            new Fact("status", "active")
        );
        
        // Test IN with multiple values
        ConditionItem inCondition = new ConditionItem(Operator.IN, "tag", Arrays.asList("urgent", "critical"));
        assertTrue(operatorHandlerComplete.handle(inCondition, complexFacts));
        
        // Test LIKE with multiple values
        ConditionItem likeCondition = new ConditionItem(Operator.LIKE, "tag", "port");
        assertTrue(operatorHandlerComplete.handle(likeCondition, complexFacts));
        
        // Test NOT_IN with multiple values
        ConditionItem notInCondition = new ConditionItem(Operator.NOT_IN, "tag", Arrays.asList("deleted", "archived"));
        assertTrue(operatorHandlerComplete.handle(notInCondition, complexFacts));
    }

    /**
     * Test performance with large fact list
     */
    @Test
    void testPerformanceWithLargeFactList() {
        // Create a large fact list
        List<Fact> largeFacts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("priority", 1),
            new Fact("category", "premium"),
            new Fact("enabled", true),
            new Fact("name", "test user"),
            new Fact("email", "test@example.com"),
            new Fact("role", "admin"),
            new Fact("department", "engineering"),
            new Fact("location", "headquarters"),
            new Fact("experience", 5)
        );
        
        ConditionItem condition = new ConditionItem(Operator.EQ, "status", "active");
        
        long startTime = System.currentTimeMillis();
        boolean result = operatorHandlerComplete.handle(condition, largeFacts);
        long endTime = System.currentTimeMillis();
        
        assertTrue(result);
        assertTrue((endTime - startTime) < 100); // Should complete within 100ms
    }
}
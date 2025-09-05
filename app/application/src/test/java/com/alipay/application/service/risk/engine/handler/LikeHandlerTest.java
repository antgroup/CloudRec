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
package com.alipay.application.service.risk.engine.handler;

import com.alipay.application.service.risk.engine.ConditionItem;
import com.alipay.application.service.risk.engine.Fact;
import com.alipay.application.service.risk.engine.Operator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for LikeHandler
 * Tests LIKE operator functionality for pattern matching
 */
class LikeHandlerTest {

    private LikeHandler likeHandler;

    @BeforeEach
    void setUp() {
        likeHandler = new LikeHandler();
    }

    /**
     * Test basic string contains matching
     */
    @Test
    void testStringContains() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "name", "test");
        List<Fact> facts = Arrays.asList(
            new Fact("name", "this is a test string"),
            new Fact("id", "123")
        );
        
        assertTrue(likeHandler.handle(condition, facts));
    }

    /**
     * Test string does not contain pattern
     */
    @Test
    void testStringDoesNotContain() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "name", "xyz");
        List<Fact> facts = Arrays.asList(
            new Fact("name", "this is a test string"),
            new Fact("id", "123")
        );
        
        assertFalse(likeHandler.handle(condition, facts));
    }

    /**
     * Test case-sensitive matching
     */
    @Test
    void testCaseSensitiveMatching() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "name", "TEST");
        List<Fact> facts = Arrays.asList(
            new Fact("name", "this is a test string"),
            new Fact("id", "123")
        );
        
        assertFalse(likeHandler.handle(condition, facts));
    }

    /**
     * Test exact string matching
     */
    @Test
    void testExactStringMatching() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "name", "test");
        List<Fact> facts = Arrays.asList(
            new Fact("name", "test"),
            new Fact("id", "123")
        );
        
        assertTrue(likeHandler.handle(condition, facts));
    }

    /**
     * Test empty pattern matching
     */
    @Test
    void testEmptyPatternMatching() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "name", "");
        List<Fact> facts = Arrays.asList(
            new Fact("name", "any string"),
            new Fact("id", "123")
        );
        
        assertTrue(likeHandler.handle(condition, facts));
    }

    /**
     * Test null pattern handling
     */
    @Test
    void testNullPatternHandling() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "name", null);
        List<Fact> facts = Arrays.asList(
            new Fact("name", "test string"),
            new Fact("id", "123")
        );
        
        assertFalse(likeHandler.handle(condition, facts));
    }

    /**
     * Test null fact value handling
     */
    @Test
    void testNullFactValueHandling() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "name", "test");
        List<Fact> facts = Arrays.asList(
            new Fact("name", null),
            new Fact("id", "123")
        );
        
        assertFalse(likeHandler.handle(condition, facts));
    }

    /**
     * Test with empty facts list
     */
    @Test
    void testEmptyFactsList() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "name", "test");
        List<Fact> facts = Collections.emptyList();
        
        assertFalse(likeHandler.handle(condition, facts));
    }

    /**
     * Test with multiple matching facts
     */
    @Test
    void testMultipleMatchingFacts() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "name", "test");
        List<Fact> facts = Arrays.asList(
            new Fact("name", "no match here"),
            new Fact("name", "this contains test"),
            new Fact("id", "123")
        );
        
        assertTrue(likeHandler.handle(condition, facts));
    }

    /**
     * Test operator type validation
     */
    @Test
    void testOperatorTypeValidation() {
        ConditionItem condition = new ConditionItem(Operator.EQ, "name", "test");
        List<Fact> facts = Arrays.asList(
            new Fact("name", "this contains test")
        );
        
        assertFalse(likeHandler.handle(condition, facts));
    }

    /**
     * Test numeric value pattern matching
     */
    @Test
    void testNumericValuePatternMatching() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "id", "123");
        List<Fact> facts = Arrays.asList(
            new Fact("id", "user123456"),
            new Fact("name", "test")
        );
        
        assertTrue(likeHandler.handle(condition, facts));
    }

    /**
     * Test special characters in pattern
     */
    @Test
    void testSpecialCharactersInPattern() {
        ConditionItem condition = new ConditionItem(Operator.LIKE, "email", "@example.com");
        List<Fact> facts = Arrays.asList(
            new Fact("email", "user@example.com"),
            new Fact("name", "test")
        );
        
        assertTrue(likeHandler.handle(condition, facts));
    }
}
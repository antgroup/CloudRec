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
 * Unit tests for NeHandler
 * Tests not-equal operator functionality with various data types
 */
class NeHandlerTest {

    private NeHandler neHandler;

    @BeforeEach
    void setUp() {
        neHandler = new NeHandler();
    }

    /**
     * Test string inequality matching
     */
    @Test
    void testStringInequality() {
        ConditionItem condition = new ConditionItem(Operator.NE, "status", "inactive");
        List<Fact> facts = Arrays.asList(
            new Fact("status", "inactive"),
            new Fact("name", "test")
        );
        
        assertTrue(neHandler.handle(condition, facts));
    }

    /**
     * Test string equality (should return false for NE)
     */
    @Test
    void testStringEquality() {
        ConditionItem condition = new ConditionItem(Operator.NE, "status", "active");
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("name", "test")
        );
        
        assertFalse(neHandler.handle(condition, facts));
    }

    /**
     * Test integer inequality matching
     */
    @Test
    void testIntegerInequality() {
        ConditionItem condition = new ConditionItem(Operator.NE, "count", 200);
        List<Fact> facts = Arrays.asList(
            new Fact("count", 200),
            new Fact("name", "test")
        );
        
        assertTrue(neHandler.handle(condition, facts));
    }

    /**
     * Test integer equality (should return false for NE)
     */
    @Test
    void testIntegerEquality() {
        ConditionItem condition = new ConditionItem(Operator.NE, "count", 100);
        List<Fact> facts = Arrays.asList(
            new Fact("count", 100),
            new Fact("name", "test")
        );
        
        assertFalse(neHandler.handle(condition, facts));
    }

    /**
     * Test null value handling
     */
    @Test
    void testNullValueHandling() {
        ConditionItem condition = new ConditionItem(Operator.NE, "value", null);
        List<Fact> facts = Arrays.asList(
            new Fact("value", "not null"),
            new Fact("name", "test")
        );
        
        assertTrue(neHandler.handle(condition, facts));
    }

    /**
     * Test null vs null comparison (should return false for NE)
     */
    @Test
    void testNullVsNullComparison() {
        ConditionItem condition = new ConditionItem(Operator.NE, "value", null);
        List<Fact> facts = Arrays.asList(
            new Fact("value", null),
            new Fact("name", "test")
        );
        
        assertFalse(neHandler.handle(condition, facts));
    }

    /**
     * Test with empty facts list
     */
    @Test
    void testEmptyFactsList() {
        ConditionItem condition = new ConditionItem(Operator.NE, "status", "active");
        List<Fact> facts = Collections.emptyList();
        
        assertFalse(neHandler.handle(condition, facts));
    }

    /**
     * Test with multiple facts (should return true if any fact is not equal)
     */
    @Test
    void testMultipleFacts() {
        ConditionItem condition = new ConditionItem(Operator.NE, "status", "active");
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("status", "inactive"),
            new Fact("name", "test")
        );
        
        assertTrue(neHandler.handle(condition, facts));
    }

    /**
     * Test operator type validation
     */
    @Test
    void testOperatorTypeValidation() {
        ConditionItem condition = new ConditionItem(Operator.EQ, "status", "active");
        List<Fact> facts = Arrays.asList(
            new Fact("status", "inactive")
        );
        
        assertFalse(neHandler.handle(condition, facts));
    }

    /**
     * Test boolean value inequality
     */
    @Test
    void testBooleanInequality() {
        ConditionItem condition = new ConditionItem(Operator.NE, "enabled", true);
        List<Fact> facts = Arrays.asList(
            new Fact("enabled", false),
            new Fact("name", "test")
        );
        
        assertTrue(neHandler.handle(condition, facts));
    }
}
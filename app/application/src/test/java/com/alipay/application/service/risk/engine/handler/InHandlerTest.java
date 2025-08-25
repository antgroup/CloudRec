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
 * Unit tests for InHandler
 * Tests IN operator functionality for collection membership
 */
class InHandlerTest {

    private InHandler inHandler;

    @BeforeEach
    void setUp() {
        inHandler = new InHandler();
    }

    /**
     * Test string value in collection
     */
    @Test
    void testStringValueInCollection() {
        ConditionItem condition = new ConditionItem(Operator.IN, "status", Arrays.asList("active", "pending", "inactive"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("id", "123")
        );
        
        assertTrue(inHandler.handle(condition, facts));
    }

    /**
     * Test string value not in collection
     */
    @Test
    void testStringValueNotInCollection() {
        ConditionItem condition = new ConditionItem(Operator.IN, "status", Arrays.asList("active", "pending", "inactive"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "deleted"),
            new Fact("id", "123")
        );
        
        assertFalse(inHandler.handle(condition, facts));
    }

    /**
     * Test integer value in collection
     */
    @Test
    void testIntegerValueInCollection() {
        ConditionItem condition = new ConditionItem(Operator.IN, "priority", Arrays.asList(1, 2, 3, 5));
        List<Fact> facts = Arrays.asList(
            new Fact("priority", 3),
            new Fact("name", "test")
        );
        
        assertTrue(inHandler.handle(condition, facts));
    }

    /**
     * Test integer value not in collection
     */
    @Test
    void testIntegerValueNotInCollection() {
        ConditionItem condition = new ConditionItem(Operator.IN, "priority", Arrays.asList(1, 2, 3, 5));
        List<Fact> facts = Arrays.asList(
            new Fact("priority", 4),
            new Fact("name", "test")
        );
        
        assertFalse(inHandler.handle(condition, facts));
    }

    /**
     * Test null value in collection containing null
     */
    @Test
    void testNullValueInCollectionWithNull() {
        ConditionItem condition = new ConditionItem(Operator.IN, "value", Arrays.asList("active", null, "inactive"));
        List<Fact> facts = Arrays.asList(
            new Fact("value", null),
            new Fact("id", "123")
        );
        
        assertTrue(inHandler.handle(condition, facts));
    }

    /**
     * Test null value in collection not containing null
     */
    @Test
    void testNullValueInCollectionWithoutNull() {
        ConditionItem condition = new ConditionItem(Operator.IN, "value", Arrays.asList("active", "pending", "inactive"));
        List<Fact> facts = Arrays.asList(
            new Fact("value", null),
            new Fact("id", "123")
        );
        
        assertFalse(inHandler.handle(condition, facts));
    }

    /**
     * Test empty collection
     */
    @Test
    void testEmptyCollection() {
        ConditionItem condition = new ConditionItem(Operator.IN, "status", Collections.emptyList());
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("id", "123")
        );
        
        assertFalse(inHandler.handle(condition, facts));
    }

    /**
     * Test null collection
     */
    @Test
    void testNullCollection() {
        ConditionItem condition = new ConditionItem(Operator.IN, "status", null);
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("id", "123")
        );
        
        assertFalse(inHandler.handle(condition, facts));
    }

    /**
     * Test with empty facts list
     */
    @Test
    void testEmptyFactsList() {
        ConditionItem condition = new ConditionItem(Operator.IN, "status", Arrays.asList("active", "pending"));
        List<Fact> facts = Collections.emptyList();
        
        assertFalse(inHandler.handle(condition, facts));
    }

    /**
     * Test with multiple facts where one matches
     */
    @Test
    void testMultipleFactsOneMatches() {
        ConditionItem condition = new ConditionItem(Operator.IN, "status", Arrays.asList("active", "pending"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "deleted"),
            new Fact("status", "active"),
            new Fact("id", "123")
        );
        
        assertTrue(inHandler.handle(condition, facts));
    }

    /**
     * Test operator type validation
     */
    @Test
    void testOperatorTypeValidation() {
        ConditionItem condition = new ConditionItem(Operator.EQ, "status", Arrays.asList("active", "pending"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active")
        );
        
        assertFalse(inHandler.handle(condition, facts));
    }

    /**
     * Test mixed data types in collection
     */
    @Test
    void testMixedDataTypesInCollection() {
        ConditionItem condition = new ConditionItem(Operator.IN, "value", Arrays.asList("string", 123, true));
        List<Fact> facts = Arrays.asList(
            new Fact("value", 123),
            new Fact("id", "test")
        );
        
        assertTrue(inHandler.handle(condition, facts));
    }

    /**
     * Test boolean value in collection
     */
    @Test
    void testBooleanValueInCollection() {
        ConditionItem condition = new ConditionItem(Operator.IN, "enabled", Arrays.asList(true, false));
        List<Fact> facts = Arrays.asList(
            new Fact("enabled", true),
            new Fact("name", "test")
        );
        
        assertTrue(inHandler.handle(condition, facts));
    }

    /**
     * Test single item collection
     */
    @Test
    void testSingleItemCollection() {
        ConditionItem condition = new ConditionItem(Operator.IN, "status", Arrays.asList("active"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("id", "123")
        );
        
        assertTrue(inHandler.handle(condition, facts));
    }

    /**
     * Test non-collection value as condition value
     */
    @Test
    void testNonCollectionConditionValue() {
        ConditionItem condition = new ConditionItem(Operator.IN, "status", "active");
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("id", "123")
        );
        
        assertFalse(inHandler.handle(condition, facts));
    }
}
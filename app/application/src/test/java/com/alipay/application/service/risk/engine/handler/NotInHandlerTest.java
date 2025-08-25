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
 * Unit tests for NotInHandler
 * Tests NOT_IN operator functionality for negative collection membership
 */
class NotInHandlerTest {

    private NotInHandler notInHandler;

    @BeforeEach
    void setUp() {
        notInHandler = new NotInHandler();
    }

    /**
     * Test string value not in collection (should return true)
     */
    @Test
    void testStringValueNotInCollection() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "status", Arrays.asList("active", "pending", "inactive"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "deleted"),
            new Fact("id", "123")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }

    /**
     * Test string value in collection (should return false)
     */
    @Test
    void testStringValueInCollection() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "status", Arrays.asList("active", "pending", "inactive"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("id", "123")
        );
        
        assertFalse(notInHandler.handle(condition, facts));
    }

    /**
     * Test integer value not in collection (should return true)
     */
    @Test
    void testIntegerValueNotInCollection() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "priority", Arrays.asList(1, 2, 3, 5));
        List<Fact> facts = Arrays.asList(
            new Fact("priority", 4),
            new Fact("name", "test")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }

    /**
     * Test integer value in collection (should return false)
     */
    @Test
    void testIntegerValueInCollection() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "priority", Arrays.asList(1, 2, 3, 5));
        List<Fact> facts = Arrays.asList(
            new Fact("priority", 3),
            new Fact("name", "test")
        );
        
        assertFalse(notInHandler.handle(condition, facts));
    }

    /**
     * Test null value not in collection containing null (should return false)
     */
    @Test
    void testNullValueInCollectionWithNull() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "value", Arrays.asList("active", null, "inactive"));
        List<Fact> facts = Arrays.asList(
            new Fact("value", null),
            new Fact("id", "123")
        );
        
        assertFalse(notInHandler.handle(condition, facts));
    }

    /**
     * Test null value not in collection not containing null (should return true)
     */
    @Test
    void testNullValueNotInCollectionWithoutNull() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "value", Arrays.asList("active", "pending", "inactive"));
        List<Fact> facts = Arrays.asList(
            new Fact("value", null),
            new Fact("id", "123")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }

    /**
     * Test empty collection (should return true)
     */
    @Test
    void testEmptyCollection() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "status", Collections.emptyList());
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("id", "123")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }

    /**
     * Test null collection (should return true)
     */
    @Test
    void testNullCollection() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "status", null);
        List<Fact> facts = Arrays.asList(
            new Fact("status", "active"),
            new Fact("id", "123")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }

    /**
     * Test with empty facts list
     */
    @Test
    void testEmptyFactsList() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "status", Arrays.asList("active", "pending"));
        List<Fact> facts = Collections.emptyList();
        
        assertFalse(notInHandler.handle(condition, facts));
    }

    /**
     * Test with multiple facts where all are not in collection
     */
    @Test
    void testMultipleFactsAllNotInCollection() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "status", Arrays.asList("active", "pending"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "deleted"),
            new Fact("status", "archived"),
            new Fact("id", "123")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }

    /**
     * Test with multiple facts where some are in collection
     */
    @Test
    void testMultipleFactsSomeInCollection() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "status", Arrays.asList("active", "pending"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "deleted"),
            new Fact("status", "active"),
            new Fact("id", "123")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }

    /**
     * Test operator type validation
     */
    @Test
    void testOperatorTypeValidation() {
        ConditionItem condition = new ConditionItem(Operator.IN, "status", Arrays.asList("active", "pending"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "deleted")
        );
        
        assertFalse(notInHandler.handle(condition, facts));
    }

    /**
     * Test mixed data types in collection
     */
    @Test
    void testMixedDataTypesNotInCollection() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "value", Arrays.asList("string", 123, true));
        List<Fact> facts = Arrays.asList(
            new Fact("value", 456),
            new Fact("id", "test")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }

    /**
     * Test boolean value not in collection
     */
    @Test
    void testBooleanValueNotInCollection() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "enabled", Arrays.asList(true));
        List<Fact> facts = Arrays.asList(
            new Fact("enabled", false),
            new Fact("name", "test")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }

    /**
     * Test single item collection
     */
    @Test
    void testSingleItemCollectionNotMatching() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "status", Arrays.asList("active"));
        List<Fact> facts = Arrays.asList(
            new Fact("status", "inactive"),
            new Fact("id", "123")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }

    /**
     * Test non-collection value as condition value
     */
    @Test
    void testNonCollectionConditionValue() {
        ConditionItem condition = new ConditionItem(Operator.NOT_IN, "status", "active");
        List<Fact> facts = Arrays.asList(
            new Fact("status", "inactive"),
            new Fact("id", "123")
        );
        
        assertTrue(notInHandler.handle(condition, facts));
    }
}
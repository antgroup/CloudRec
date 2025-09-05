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
package com.alipay.application.service.resource.enums;

/**
 * Enumeration for asset aggregation types
 * Defines how assets should be grouped and aggregated in queries
 * 
 * @author jietian
 * @version 1.0
 */
public enum AggregationType {
    
    /**
     * Aggregate assets by resource type
     * Groups assets based on their resource type classification
     */
    RESOURCE_TYPE("RESOURCE_TYPE", "Aggregate by resource type"),
    
    /**
     * Aggregate assets by cloud account
     * Groups assets based on their associated cloud account
     */
    CLOUD_ACCOUNT("CLOUD_ACCOUNT", "Aggregate by cloud account");
    
    private final String code;
    private final String description;
    
    /**
     * Constructor for AggregationType enum
     * 
     * @param code the string code representing the aggregation type
     * @param description human-readable description of the aggregation type
     */
    AggregationType(String code, String description) {
        this.code = code;
        this.description = description;
    }
    
    /**
     * Get the string code for this aggregation type
     * 
     * @return the code string
     */
    public String getCode() {
        return code;
    }
    
    /**
     * Get the description for this aggregation type
     * 
     * @return the description string
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Find AggregationType by code string
     * 
     * @param code the code string to match
     * @return the matching AggregationType, or null if not found
     */
    public static AggregationType fromCode(String code) {
        if (code == null) {
            return null;
        }
        
        for (AggregationType type : values()) {
            if (type.getCode().equals(code)) {
                return type;
            }
        }
        
        return null;
    }
    
    /**
     * Check if the given code represents a valid aggregation type
     * 
     * @param code the code string to validate
     * @return true if the code is valid, false otherwise
     */
    public static boolean isValidCode(String code) {
        return fromCode(code) != null;
    }
}
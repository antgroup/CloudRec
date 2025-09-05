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
package com.alipay.application.share.vo.whited;

import com.alipay.dao.dto.GroupByRuleCodeDTO;
import lombok.Data;

import java.io.Serializable;

/**
 * Date: 2025/3/20
 * Author: lz
 */

@Data
public class GroupByRuleCodeVO implements Serializable {

    private static final String GLOBAL_CONFIG = "GLOBAL_CONFIG";

    private Long id;

    private String ruleName;

    private String ruleCode;

    private Integer count;

    private String platform;


    public static GroupByRuleCodeVO build(GroupByRuleCodeDTO dto) {
        GroupByRuleCodeVO groupByRuleCodeVO = new GroupByRuleCodeVO();
        groupByRuleCodeVO.setRuleName(dto.getRuleName());
        groupByRuleCodeVO.setRuleCode(dto.getRuleCode());
        groupByRuleCodeVO.setCount(dto.getCount());
        groupByRuleCodeVO.setPlatform(dto.getPlatform());

        if (dto.getRuleCode() == null) {
            groupByRuleCodeVO.setRuleCode(GLOBAL_CONFIG);
            groupByRuleCodeVO.setRuleName(GLOBAL_CONFIG);
        }

        return groupByRuleCodeVO;
    }

}

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
package com.alipay.dao.mapper;

import com.alipay.dao.dto.GroupByRuleCodeDTO;
import com.alipay.dao.dto.QueryWhitedRuleDTO;
import com.alipay.dao.po.WhitedRuleConfigPO;

import java.util.List;

public interface WhitedRuleConfigMapper {
    int deleteByPrimaryKey(Long id);

    int insert(WhitedRuleConfigPO row);

    int insertSelective(WhitedRuleConfigPO row);

    WhitedRuleConfigPO selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(WhitedRuleConfigPO row);

    int updateByPrimaryKey(WhitedRuleConfigPO row);

    int count(QueryWhitedRuleDTO queryWhitedRuleDTO);

    List<WhitedRuleConfigPO> list(QueryWhitedRuleDTO dto);

    GroupByRuleCodeDTO findNullRuleCode(QueryWhitedRuleDTO dto);

    List<GroupByRuleCodeDTO> findListGroupByRuleCode(QueryWhitedRuleDTO dto);
}
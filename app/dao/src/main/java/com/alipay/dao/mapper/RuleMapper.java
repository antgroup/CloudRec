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

import com.alipay.dao.dto.RuleDTO;
import com.alipay.dao.po.RulePO;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface RuleMapper {
    int deleteByPrimaryKey(Long id);

    int insertSelective(RulePO record);

    RulePO selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(RulePO record);

    int findCount(RuleDTO ruleDTO);

    List<RulePO> findList(RuleDTO ruleDTO);

    List<RulePO> findAll();

    List<RulePO> findSortList(RuleDTO ruleDTO);

    int updateStatus(@Param("id") Long id, @Param("status") String status);

    RulePO findOne(String code);

    List<RulePO> findByIdList(@Param("idList") List<Long> idList);

    RulePO findOneByCond(@Param("platform") String platform, @Param("ruleName") String ruleName);

}
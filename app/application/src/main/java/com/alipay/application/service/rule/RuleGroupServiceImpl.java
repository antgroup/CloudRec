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
package com.alipay.application.service.rule;
/*
 *@title RuleGroupServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/5 19:00
 */

import com.alipay.application.service.rule.domain.RuleGroup;
import com.alipay.application.service.rule.domain.repo.RuleGroupConverter;
import com.alipay.application.service.rule.domain.repo.RuleGroupRepository;
import com.alipay.application.share.request.rule.RuleGroupRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleGroupVO;
import com.alipay.application.share.vo.rule.RuleVO;
import com.alipay.common.exception.BizException;
import com.alipay.dao.dto.RuleDTO;
import com.alipay.dao.dto.RuleGroupDTO;
import com.alipay.dao.mapper.RuleGroupMapper;
import com.alipay.dao.mapper.RuleGroupRelMapper;
import com.alipay.dao.mapper.RuleMapper;
import com.alipay.dao.po.RuleGroupPO;
import com.alipay.dao.po.RulePO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
public class RuleGroupServiceImpl implements RuleGroupService {

    @Resource
    private RuleGroupMapper ruleGroupMapper;
    @Resource
    private RuleMapper ruleMapper;
    @Resource
    private RuleGroupRelMapper ruleGroupRelMapper;
    @Resource
    private RuleGroupRepository ruleGroupRepository;
    @Resource
    private RuleGroupConverter ruleGroupConverter;

    @Transactional(rollbackFor = Exception.class)
    @Override
    public ApiResponse<String> deleteRuleGroup(Long id) {
        ruleGroupMapper.deleteByPrimaryKey(id);
        ruleGroupRelMapper.deleteByRuleGroupId(id);
        return ApiResponse.SUCCESS;
    }


    @Override
    public ApiResponse<ListVO<RuleGroupVO>> queryRuleGroupList(RuleGroupRequest request) {
        RuleGroupDTO ruleGroupDTO = RuleGroupDTO.builder().build();
        BeanUtils.copyProperties(request, ruleGroupDTO);

        ListVO<RuleGroupVO> listVO = new ListVO<>();
        int count = ruleGroupMapper.findCount(ruleGroupDTO);
        if (count == 0) {
            return new ApiResponse<>(listVO);
        }

        int defaultWebPageSize = 10;
        if (request.getSize() != defaultWebPageSize) {
            ruleGroupDTO.setOffset();
        }

        List<RuleGroupPO> list = ruleGroupMapper.findList(ruleGroupDTO);
        List<RuleGroupVO> collect = list.stream().map(RuleGroupVO::build).collect(Collectors.toList());
        listVO.setData(collect);
        listVO.setTotal(count);
        return new ApiResponse<>(listVO);
    }


    @Override
    public ApiResponse<String> saveRuleGroup(RuleGroupDTO dto) {
        if (dto.getId() == null) {
            RuleGroupPO ruleGroupPO = ruleGroupMapper.findOne(dto.getGroupName());
            if (ruleGroupPO != null) {
                throw new BizException("The rule group name already exists");
            }
        }

        RuleGroupPO ruleGroupPO = new RuleGroupPO();
        BeanUtils.copyProperties(dto, ruleGroupPO);

        // Save rule groups
        RuleGroup ruleGroup = ruleGroupConverter.toEntity(ruleGroupPO);
        long groupId = ruleGroupRepository.save(ruleGroup);

        // Related Rules
        ruleGroupRepository.join(groupId, dto.getRuleIdList());

        return ApiResponse.SUCCESS;
    }

    @Override
    public List<String> queryRuleGroupNameList() {
        RuleGroupDTO ruleGroupDTO = RuleGroupDTO.builder().build();
        List<RuleGroupPO> ruleGroupPOS = ruleGroupMapper.findList(ruleGroupDTO);
        return ruleGroupPOS.stream().map(RuleGroupPO::getGroupName).distinct().collect(Collectors.toList());
    }

    @Override
    public ApiResponse<RuleGroupVO> queryRuleGroupDetail(Long id) {
        RuleGroupPO ruleGroupPO = ruleGroupMapper.selectByPrimaryKey(id);
        if (ruleGroupPO == null) {
            throw new BizException("The rule group does not exist");
        }

        RuleGroupVO ruleGroupVO = new RuleGroupVO();
        ruleGroupVO.setGroupName(ruleGroupPO.getGroupName());
        ruleGroupVO.setGroupDesc(ruleGroupPO.getGroupDesc());
        ruleGroupVO.setId(ruleGroupPO.getId());

        // Query the rule list associated with the rule group
        RuleDTO ruleDTO = RuleDTO.builder().ruleGroupId(id).build();
        List<RulePO> list = ruleMapper.findList(ruleDTO);
        if (!CollectionUtils.isEmpty(list)) {
            ruleGroupVO.setAboutRuleList(list.stream().map(RuleVO::buildEasy).toList());
        }

        return new ApiResponse<>(ruleGroupVO);
    }
}

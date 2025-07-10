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
package com.alipay.application.service.rule.impl;

import com.alibaba.fastjson.JSON;
import com.alipay.application.service.common.WhitedConfigType;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.application.service.risk.RiskService;
import com.alipay.application.service.risk.RiskStatusManager;
import com.alipay.application.service.risk.engine.ConditionAssembler;
import com.alipay.application.service.risk.engine.ConditionItem;
import com.alipay.application.service.risk.engine.Operator;
import com.alipay.application.service.rule.WhitedExampleDataComponent;
import com.alipay.application.service.rule.WhitedRegoMatcher;
import com.alipay.application.service.rule.WhitedRuleEngineMatcher;
import com.alipay.application.service.rule.WhitedRuleService;
import com.alipay.application.service.rule.job.ScanService;
import com.alipay.application.service.system.domain.User;
import com.alipay.application.service.system.domain.repo.UserRepository;
import com.alipay.application.share.request.rule.*;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleScanResultVO;
import com.alipay.application.share.vo.rule.RuleVO;
import com.alipay.application.share.vo.whited.WhitedConfigVO;
import com.alipay.application.share.vo.whited.WhitedRuleConfigVO;
import com.alipay.common.enums.WhitedRuleOperatorEnum;
import com.alipay.common.enums.WhitedRuleTypeEnum;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.context.UserInfoDTO;
import com.alipay.dao.dto.QueryScanResultDTO;
import com.alipay.dao.dto.QueryWhitedRuleDTO;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.mapper.RuleMapper;
import com.alipay.dao.mapper.RuleScanResultMapper;
import com.alipay.dao.mapper.WhitedRuleConfigMapper;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.RulePO;
import com.alipay.dao.po.RuleScanResultPO;
import com.alipay.dao.po.WhitedRuleConfigPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.*;

/**
 * Date: 2025/3/13
 * Author: lz
 */
@Slf4j
@Service
public class WhitedRuleServiceImpl implements WhitedRuleService {

    @Resource
    private WhitedRuleConfigMapper whitedRuleConfigMapper;

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private WhitedRuleEngineMatcher whitedRuleEngineMatcher;

    @Resource
    private WhitedRegoMatcher whitedRegoMatcher;

    @Resource
    private RuleMapper ruleMapper;

    @Resource
    private WhitedExampleDataComponent whitedExampleDataComponent;

    @Resource
    private RiskService riskService;

    @Resource
    private ScanService scanService;

    private static final ExecutorService executorService = new ThreadPoolExecutor(
            8,
            8,
            1L,
            TimeUnit.MINUTES,
            new LinkedBlockingQueue<>(1000),
            Executors.defaultThreadFactory(),
            new ThreadPoolExecutor.CallerRunsPolicy()
    );


    @Override
    public int save(SaveWhitedRuleRequestDTO dto) throws RuntimeException {
        UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
        paramCheck(dto, currentUser);
        WhitedRuleConfigPO whitedRuleConfigPO = new WhitedRuleConfigPO();
        //处理白名单规则详情
        String ruleConfigJson = null;
        List<WhitedRuleConfigDTO> ruleConfigList = dto.getRuleConfigList();
        if (!CollectionUtils.isEmpty(ruleConfigList)) {
            Map<Integer, ConditionItem> conditionItemMap = new HashMap<>();
            for (WhitedRuleConfigDTO config : ruleConfigList) {
                conditionItemMap.put(config.getId(), new ConditionItem(config.getId(), config.getKey(), Operator.valueOf(config.getOperator().name()), config.getValue()));
            }

            try {
                ruleConfigJson = ConditionAssembler.generateJsonCond(conditionItemMap, dto.getCondition());
            } catch (Exception e) {
                log.error("ruleName: {} create condition failed, condition:{}, error:", dto.getRuleName(), dto.getCondition(), e);
                throw new RuntimeException(dto.getRuleName() + ": condition is not valid");
            }
        }

        if (Objects.nonNull(dto.getId())) {
            whitedRuleConfigPO = whitedRuleConfigMapper.selectByPrimaryKey(dto.getId());
            if (Objects.nonNull(whitedRuleConfigPO)) {
                if (!currentUser.getUserId().equals(whitedRuleConfigPO.getLockHolder())) {
                    log.error("save whitedRuleConfig error, lockHolder and current user different， whitedRuleId: {} , lockHolder:{}， currentUser:{} ", whitedRuleConfigPO.getId(), whitedRuleConfigPO.getLockHolder(), currentUser.getUserId());
                    throw new RuntimeException("当前规则已被其他用户锁定,请抢锁并重试!");
                }
                //更新数据
                buildWhitedRuleConfigPO(whitedRuleConfigPO, dto, currentUser, ruleConfigJson);
                whitedRuleConfigPO.setGmtModified(new Date());
                return whitedRuleConfigMapper.updateByPrimaryKeySelective(whitedRuleConfigPO);
            } else {
                throw new RuntimeException("whitedRuleConfigPO id: " + dto.getId() + "不存在,请检查!");
            }
        }
        buildWhitedRuleConfigPO(whitedRuleConfigPO, dto, currentUser, ruleConfigJson);
        whitedRuleConfigPO.setEnable(dto.getEnable());
        int insertResult = whitedRuleConfigMapper.insertSelective(whitedRuleConfigPO);
        if (insertResult > 0 && dto.getEnable() == 1 && WhitedRuleTypeEnum.RULE_ENGINE.name().equals(dto.getRuleType()) && !StringUtils.isEmpty(dto.getRiskRuleCode())) {
            //触发风险扫描
            RulePO rulePO = ruleMapper.findOne(dto.getRiskRuleCode());
            executorService.execute(() -> {
                scanService.scanByRule(rulePO.getId());
            });
        }
        return insertResult;
    }

    @Override
    public ListVO<WhitedRuleConfigVO> getList(QueryWhitedRuleDTO dto) {
        ListVO<WhitedRuleConfigVO> listVO = new ListVO<>();
        if (!StringUtils.isEmpty(dto.getCreatorName())) {
            UserRepository userRepository = SpringUtils.getApplicationContext().getBean(UserRepository.class);
            User user = userRepository.findByUserName(dto.getCreatorName());
            if (Objects.isNull(user)) {
                return null;
            } else {
                dto.setCreator(user.getUserId());
            }
        }

        dto.setTenantId(UserInfoContext.getCurrentUser().getTenantId());
        List<WhitedRuleConfigPO> list = whitedRuleConfigMapper.list(dto);
        if (StringUtils.isNoneEmpty(dto.getSearch())) {
            list = list.stream()
                    .filter(po -> po.getRuleConfig().contains(dto.getSearch()) || po.getRegoContent().contains(dto.getSearch()))
                    .toList();
        }

        List<WhitedRuleConfigVO> result = list.stream()
                .skip((long) (dto.getPage() - 1) * dto.getSize())
                .limit(dto.getSize())
                .map(this::convertToVO)
                .toList();

        listVO.setTotal(list.size());
        listVO.setData(result);

        return listVO;
    }

    private WhitedRuleConfigVO convertToVO(WhitedRuleConfigPO whitedRuleConfigPO) {
        UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
        WhitedRuleConfigVO vo = new WhitedRuleConfigVO();
        BeanUtils.copyProperties(whitedRuleConfigPO, vo);

        UserRepository userRepository = SpringUtils.getApplicationContext().getBean(UserRepository.class);
        User user = userRepository.find(whitedRuleConfigPO.getCreator());
        vo.setCreatorName(user.getUsername());

        boolean isLockHolder = false;
        if (currentUser.getUserId().equals(whitedRuleConfigPO.getLockHolder())) {
            isLockHolder = true;
            vo.setLockHolderName(currentUser.getUsername());
        } else {
            User lockHolder = userRepository.find(whitedRuleConfigPO.getLockHolder());
            if (lockHolder != null) {
                vo.setLockHolderName(lockHolder.getUsername());
            }
        }
        vo.setIsLockHolder(isLockHolder);
        return vo;
    }

    @Override
    public WhitedRuleConfigVO getById(Long id) {
        WhitedRuleConfigPO whitedRuleConfigPO = whitedRuleConfigMapper.selectByPrimaryKey(id);
        return convertToVO(whitedRuleConfigPO);
    }

    @Override
    public int deleteById(Long id) {
        WhitedRuleConfigPO whitedRuleConfigPO = whitedRuleConfigMapper.selectByPrimaryKey(id);
        if (Objects.isNull(whitedRuleConfigPO)) {
            throw new RuntimeException("当前规则不存在,请检查!");
        }
        UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
        if (!currentUser.getUserId().equals(whitedRuleConfigPO.getLockHolder())) {
            log.error("deleteById whitedRuleConfig error, lockHolder and current user different， whitedRuleid: {} , lockHolder:{}， currentUser:{} ", whitedRuleConfigPO.getId(), whitedRuleConfigPO.getLockHolder(), currentUser.getUserId());
            throw new RuntimeException("当前规则已被其他用户锁定,请抢锁并重试!");
        }
        return whitedRuleConfigMapper.deleteByPrimaryKey(id);
    }

    @Override
    public void changeStatus(Long id, int enable) {
        WhitedRuleConfigPO whitedRuleConfigPO = whitedRuleConfigMapper.selectByPrimaryKey(id);
        if (Objects.nonNull(whitedRuleConfigPO)) {
            UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
            if (!currentUser.getUserId().equals(whitedRuleConfigPO.getLockHolder())) {
                log.error("deleteById whitedRuleConfig error, lockHolder and current user different， whitedRuleid: {} , lockHolder:{}， currentUser:{} ", whitedRuleConfigPO.getId(), whitedRuleConfigPO.getLockHolder(), currentUser.getUserId());
                throw new RuntimeException("当前规则已被其他用户锁定,请抢锁并重试!");
            }
            whitedRuleConfigPO.setEnable(enable);
            whitedRuleConfigPO.setGmtModified(new Date());
            whitedRuleConfigMapper.updateByPrimaryKeySelective(whitedRuleConfigPO);
        } else {
            throw new RuntimeException("whitedRuleConfigPO id: " + id + "不存在,请检查!");
        }
    }


    @Override
    public void grabLock(Long id) {
        WhitedRuleConfigPO whitedRuleConfigPO = whitedRuleConfigMapper.selectByPrimaryKey(id);
        if (Objects.nonNull(whitedRuleConfigPO)) {
            whitedRuleConfigPO.setLockHolder(UserInfoContext.getCurrentUser().getUserId());
            whitedRuleConfigPO.setGmtModified(new Date());
            whitedRuleConfigMapper.updateByPrimaryKeySelective(whitedRuleConfigPO);
        } else {
            throw new RuntimeException("whitedRuleConfigPO id: " + id + "不存在,请检查!");
        }
    }

    @Override
    public List<WhitedConfigVO> getWhitedConfigList() {
        WhitedConfigType.initData();
        List<WhitedConfigVO> whitedConfigList = new ArrayList<>();
        for (WhitedConfigType whitedConfigType : WhitedConfigType.values()) {
            WhitedConfigVO whitedConfigVO = new WhitedConfigVO();
            whitedConfigVO.setKey(whitedConfigType.name());
            whitedConfigVO.setKeyName(whitedConfigType.getKeyName());
            whitedConfigVO.setOperatorList(whitedConfigType.getOperatorList());
            whitedConfigVO.setValue(whitedConfigType.getValue());
            whitedConfigList.add(whitedConfigVO);
        }
        return whitedConfigList;
    }

    @Override
    public WhitedScanInputDataDTO queryExampleData(String riskRuleCode) {
        //基于规则code选择一条未处理的风险数据
        WhitedScanInputDataDTO whitedExampleDataResultDTO = new WhitedScanInputDataDTO();
        RuleScanResultDTO dto = RuleScanResultDTO.builder()
                .status(RiskStatusManager.RiskStatus.UNREPAIRED.name())
                .ruleCodeList(Collections.singletonList(riskRuleCode))
                .build();
        List<RuleScanResultPO> ruleScanResultList = ruleScanResultMapper.findList(dto);
        if (!CollectionUtils.isEmpty(ruleScanResultList)) {
            RuleScanResultPO ruleScanResultPO = ruleScanResultList.get(0);
            whitedExampleDataResultDTO = whitedExampleDataComponent.buildWhitedExampleDataResultDTO(ruleScanResultPO, null, null);
        }
        return whitedExampleDataResultDTO;
    }

    @Override
    public TestRunWhitedRuleResultDTO testRun(TestRunWhitedRuleRequestDTO dto) {

        testRunParamCheck(dto);

        List<RuleScanResultPO> preWhitedList = new ArrayList<>();
        int count = 0;
        //获取当前租户下的风险数据
        QueryScanResultDTO queryScanResultDTO = new QueryScanResultDTO();
        queryScanResultDTO.setTenantId(UserInfoContext.getCurrentUser().getTenantId());
        queryScanResultDTO.setLimit(100);

        String scrollId = null;
        if (!StringUtils.isEmpty(dto.getRiskRuleCode())) {
            RulePO rulePO = ruleMapper.findOne(dto.getRiskRuleCode());
            if (Objects.isNull(rulePO)) {
                return TestRunWhitedRuleResultDTO.builder()
                        .count(0)
                        .build();
            }
            queryScanResultDTO.setRuleId(rulePO.getId());
        }
        List<RuleScanResultPO> listWithScrollId = new ArrayList<>();
        while (true) {
            queryScanResultDTO.setScrollId(scrollId);
            listWithScrollId = ruleScanResultMapper.findListWithScrollId(queryScanResultDTO);
            if (CollectionUtils.isEmpty(listWithScrollId)) {
                break;
            }
            scrollId = listWithScrollId.get(listWithScrollId.size() - 1).getId().toString();
            for (RuleScanResultPO ruleScanResultPO : listWithScrollId) {
                if (!StringUtils.isEmpty(dto.getRiskRuleCode())) {
                    RulePO rulePO = ruleMapper.selectByPrimaryKey(ruleScanResultPO.getRuleId());
                    if (Objects.isNull(rulePO) || StringUtils.isEmpty(rulePO.getRuleCode()) || !rulePO.getRuleCode().equals(dto.getRiskRuleCode())) {
                        continue;
                    }
                }

                //执行白名单扫描
                boolean isWhited = false;
                if (dto.getRuleType().equals(WhitedRuleTypeEnum.RULE_ENGINE.name())) {
                    isWhited = executeRuleEngineScan(dto, ruleScanResultPO);
                } else if (dto.getRuleType().equals(WhitedRuleTypeEnum.REGO.name())) {
                    //REGO规则引擎扫描器执行
                    isWhited = executeTestRegoScan(dto, ruleScanResultPO, null);
                }
                if (isWhited) {
                    count++;
                    if (preWhitedList.size() < 30) {
                        preWhitedList.add(ruleScanResultPO);
                    }
                }
            }
        }

        TestRunWhitedRuleResultDTO resultDTO = TestRunWhitedRuleResultDTO.builder()
                .count(count)
                .ruleScanResultList(preWhitedList)
                .build();

        return resultDTO;
    }

    @Override
    public SaveWhitedRuleRequestDTO queryWhitedContentByRisk(Long riskId) {
        ApiResponse<RuleScanResultVO> ruleScanResultVOApiResponse = riskService.queryRiskDetail(riskId);
        if (!StringUtils.isEmpty(ruleScanResultVOApiResponse.getErrorCode()) || Objects.isNull(ruleScanResultVOApiResponse.getContent())) {
            log.error("query RuleScanResultVO not exist,riskId:{} ", riskId);
            return null;
        }
        return buildContentByRiskInfo(ruleScanResultVOApiResponse.getContent());
    }

    private SaveWhitedRuleRequestDTO buildContentByRiskInfo(RuleScanResultVO ruleScanResultVO) {
        RuleVO ruleVO = ruleScanResultVO.getRuleVO();
        SaveWhitedRuleRequestDTO saveWhitedRuleRequestDTO = new SaveWhitedRuleRequestDTO();
        saveWhitedRuleRequestDTO.setRuleName(ruleVO.getRuleName() + "_手动加白");
        saveWhitedRuleRequestDTO.setRuleDesc(ruleVO.getRuleName() + "_手动加白");
        saveWhitedRuleRequestDTO.setRuleType(WhitedRuleTypeEnum.RULE_ENGINE.name());
        saveWhitedRuleRequestDTO.setRiskRuleCode(ruleScanResultVO.getRuleCode());

        List<WhitedRuleConfigDTO> ruleConfigList = new ArrayList<>();
        int index = 1;
        if (!StringUtils.isEmpty(ruleScanResultVO.getResourceId())) {
            WhitedRuleConfigDTO resourceIdRuleConfigDTO = WhitedRuleConfigDTO.builder()
                    .id(index)
                    .key("resourceId")
                    .operator(WhitedRuleOperatorEnum.EQ)
                    .value(ruleScanResultVO.getResourceId())
                    .build();
            index++;
            ruleConfigList.add(resourceIdRuleConfigDTO);
        }
        if (!StringUtils.isEmpty(ruleScanResultVO.getCloudAccountId())) {
            WhitedRuleConfigDTO resourceTypeRuleConfigDTO = WhitedRuleConfigDTO.builder()
                    .id(index)
                    .key("resourceType")
                    .operator(WhitedRuleOperatorEnum.EQ)
                    .value(ruleScanResultVO.getResourceType())
                    .build();
            index++;
            ruleConfigList.add(resourceTypeRuleConfigDTO);
        }
        if (!StringUtils.isEmpty(ruleScanResultVO.getCloudAccountId())) {
            WhitedRuleConfigDTO cloudAccountIdRuleConfigDTO = WhitedRuleConfigDTO.builder()
                    .id(index)
                    .key("cloudAccountId")
                    .operator(WhitedRuleOperatorEnum.EQ)
                    .value(ruleScanResultVO.getCloudAccountId())
                    .build();
            ruleConfigList.add(cloudAccountIdRuleConfigDTO);
        }
        StringBuilder condition = new StringBuilder();
        for (int i = 1; i <= index; i++) {
            condition.append(i);
            if (i < index) {
                condition.append("&&");
            }
        }
        saveWhitedRuleRequestDTO.setCondition(condition.toString());
        saveWhitedRuleRequestDTO.setRuleConfigList(ruleConfigList);
        return saveWhitedRuleRequestDTO;
    }

    private TestRunWhitedRuleResultDTO runRegoWithInput(TestRunWhitedRuleRequestDTO dto) {
        //rego模式下且选择了风险规则
        if (dto.getRuleType().equals(WhitedRuleTypeEnum.REGO.name()) && !StringUtils.isEmpty(dto.getRiskRuleCode())) {

            RuleScanResultDTO ruleScanResultDTO = RuleScanResultDTO.builder()
                    .status(RiskStatusManager.RiskStatus.UNREPAIRED.name())
                    .ruleCodeList(Collections.singletonList(dto.getRiskRuleCode()))
                    .build();

            List<RuleScanResultPO> ruleScanResultList = ruleScanResultMapper.findList(ruleScanResultDTO);
            RuleScanResultPO ruleScanResultPO = null;
            if (!CollectionUtils.isEmpty(ruleScanResultList)) {
                ruleScanResultPO = ruleScanResultList.get(0);
            }
            WhitedScanInputDataDTO whitedExampleDataResultDTO = JSON.parseObject(dto.getInput(), WhitedScanInputDataDTO.class);

            // 无示例数据的情况
            if (!areAllFieldsNull(whitedExampleDataResultDTO)) {
                boolean scanResult = executeRegoScan(dto, whitedExampleDataResultDTO);
                if (scanResult) {
                    return TestRunWhitedRuleResultDTO.builder()
                            .count(1)
                            .ruleScanResultList(Collections.singletonList(ruleScanResultPO))
                            .build();
                }
            }
        }
        return TestRunWhitedRuleResultDTO.builder()
                .count(0)
                .build();
    }

    private void testRunParamCheck(TestRunWhitedRuleRequestDTO dto) {
        if (WhitedRuleTypeEnum.REGO.name().equals(dto.getRuleType()) && StringUtils.isEmpty(dto.getRegoContent())) {
            throw new RuntimeException("REGO规则内容为空,请检查!");
        }
        if (!WhitedRuleTypeEnum.exist(dto.getRuleType())) {
            throw new RuntimeException("规则类型不存在,请检查!");
        }
        if (WhitedRuleTypeEnum.RULE_ENGINE.name().equals(dto.getRuleType())) {
            if (!CollectionUtils.isEmpty(dto.getRuleConfigList()) && dto.getRuleConfigList().size() == 1 && StringUtils.isEmpty(dto.getCondition())) {
                dto.setCondition("1");
            }
            if (!CollectionUtils.isEmpty(dto.getRuleConfigList()) && dto.getRuleConfigList().size() > 1 && StringUtils.isEmpty(dto.getCondition())) {
                throw new RuntimeException("存在多个条件配置规则,请设置其逻辑关系!");
            }
        }
    }

    private void paramCheck(SaveWhitedRuleRequestDTO dto, UserInfoDTO userInfo) {
        if (Objects.isNull(userInfo)) {
            throw new RuntimeException("用户信息为空,请检查!");
        }
        if (!WhitedRuleTypeEnum.exist(dto.getRuleType())) {
            throw new RuntimeException("规则类型不存在,请检查!");
        }
        if (WhitedRuleTypeEnum.REGO.name().equals(dto.getRuleType()) && StringUtils.isEmpty(dto.getRegoContent())) {
            throw new RuntimeException("REGO规则内容为空,请检查!");
        }
        if (WhitedRuleTypeEnum.RULE_ENGINE.name().equals(dto.getRuleType())) {
            if (!CollectionUtils.isEmpty(dto.getRuleConfigList()) && dto.getRuleConfigList().size() > 1 && StringUtils.isEmpty(dto.getCondition())) {
                throw new RuntimeException("存在多个条件配置规则,请设置其逻辑关系!");
            }
            if (!CollectionUtils.isEmpty(dto.getRuleConfigList()) && dto.getRuleConfigList().size() == 1 && StringUtils.isEmpty(dto.getCondition())) {
                dto.setCondition("1");
            }
        }


        if (Objects.isNull(dto.getId())) {
            QueryWhitedRuleDTO queryWhitedRuleDTO = QueryWhitedRuleDTO.builder()
                    .ruleType(dto.getRuleType())
                    .ruleName(dto.getRuleName())
                    .build();
            List<WhitedRuleConfigPO> list = whitedRuleConfigMapper.list(queryWhitedRuleDTO);
            if (!CollectionUtils.isEmpty(list)) {
                throw new RuntimeException("当前规则类型存在重复规则名,请修改!");
            }
        }
    }

    private WhitedRuleConfigPO buildWhitedRuleConfigPO(WhitedRuleConfigPO whitedRuleConfigPO, SaveWhitedRuleRequestDTO dto, UserInfoDTO userInfo, String ruleConfigJson) {
        whitedRuleConfigPO.setRuleName(dto.getRuleName());
        whitedRuleConfigPO.setRuleDesc(dto.getRuleDesc());
        whitedRuleConfigPO.setRuleType(dto.getRuleType());
        whitedRuleConfigPO.setRuleConfig(JSON.toJSONString(dto.getRuleConfigList()));
        whitedRuleConfigPO.setRuleConfigJson(ruleConfigJson);
        whitedRuleConfigPO.setCondition(dto.getCondition());
        whitedRuleConfigPO.setRegoContent(dto.getRegoContent());
        if (Objects.isNull(whitedRuleConfigPO.getId())) {
            whitedRuleConfigPO.setCreator(userInfo.getUserId());
        }
        whitedRuleConfigPO.setLockHolder(userInfo.getUserId());
        whitedRuleConfigPO.setTenantId(userInfo.getTenantId());
        whitedRuleConfigPO.setRiskRuleCode(dto.getRiskRuleCode());
        return whitedRuleConfigPO;
    }

    /**
     * 普通规则引擎扫描器执行
     *
     * @param dto
     * @param ruleScanResultPO
     */
    private boolean executeRuleEngineScan(TestRunWhitedRuleRequestDTO dto, RuleScanResultPO ruleScanResultPO) {
        return whitedRuleEngineMatcher.matchWhitelistRule(dto.getRuleConfigList(), dto.getCondition(), ruleScanResultPO);
    }

    /**
     * REGO规则引擎扫描器执行
     *
     * @param dto
     * @param ruleScanResultPO
     * @return
     */
    private boolean executeTestRegoScan(TestRunWhitedRuleRequestDTO dto, RuleScanResultPO ruleScanResultPO, CloudAccountPO cloudAccountPO) {
        return whitedRegoMatcher.executeRegoMatch(dto.getRegoContent(), null, ruleScanResultPO, cloudAccountPO, null);
    }

    /**
     * REGO规则引擎扫描器执行-
     *
     * @param dto
     * @param whitedScanInputDataDTO
     * @return
     */
    private boolean executeRegoScan(TestRunWhitedRuleRequestDTO dto, WhitedScanInputDataDTO whitedScanInputDataDTO) {
        return whitedRegoMatcher.executeRegoMatch(dto.getRegoContent(), null, whitedScanInputDataDTO);
    }


    public static boolean areAllFieldsNull(WhitedScanInputDataDTO whitedScanInputDataDTO) {
        if (whitedScanInputDataDTO == null) {
            return true;
        }
        // 遍历所有字段
        for (Field field : whitedScanInputDataDTO.getClass().getDeclaredFields()) {
            field.setAccessible(true);
            try {
                Object value = field.get(whitedScanInputDataDTO);
                if (value != null) {
                    if (value instanceof String && !((String) value).trim().isEmpty()) {
                        return false;
                    } else if (!(value instanceof String)) {
                        return false;
                    }
                }
            } catch (IllegalAccessException e) {
                log.error("areAllFieldsNull error", e);
            }
        }

        return true;
    }
}

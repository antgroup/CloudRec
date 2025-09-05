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
import com.alipay.application.service.rule.job.context.TenantWhitedConfigContextV2;
import com.alipay.application.service.system.domain.User;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.application.service.system.domain.repo.UserRepository;
import com.alipay.application.share.request.rule.*;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleScanResultVO;
import com.alipay.application.share.vo.rule.RuleVO;
import com.alipay.application.share.vo.whited.GroupByRuleCodeVO;
import com.alipay.application.share.vo.whited.WhitedConfigVO;
import com.alipay.application.share.vo.whited.WhitedRuleConfigVO;
import com.alipay.common.enums.WhitedRuleOperatorEnum;
import com.alipay.common.enums.WhitedRuleTypeEnum;
import com.alipay.common.exception.BizException;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.context.UserInfoDTO;
import com.alipay.dao.dto.GroupByRuleCodeDTO;
import com.alipay.dao.dto.QueryScanResultDTO;
import com.alipay.dao.dto.QueryWhitedRuleDTO;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.mapper.RuleMapper;
import com.alipay.dao.mapper.RuleScanResultMapper;
import com.alipay.dao.mapper.TenantMapper;
import com.alipay.dao.mapper.WhitedRuleConfigMapper;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Stream;

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

    @Resource
    private TenantRepository tenantRepository;

    @Resource
    private TenantWhitedConfigContextV2 tenantWhitedConfigContextV2;

    private static final ExecutorService executorService = new ThreadPoolExecutor(
            8,
            8,
            1L,
            TimeUnit.MINUTES,
            new LinkedBlockingQueue<>(1000),
            Executors.defaultThreadFactory(),
            new ThreadPoolExecutor.CallerRunsPolicy()
    );
    @Autowired
    private TenantMapper tenantMapper;


    @Override
    public Long save(SaveWhitedRuleRequest dto) throws RuntimeException {
        UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
        permissionCheck(dto.getId());
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
                    throw new RuntimeException("The current whitelist has been locked by other users, please grab the lock and try again!");
                }

                tenantWhitedConfigContextV2.clearAllCache();
                //更新数据
                buildWhitedRuleConfigPO(whitedRuleConfigPO, dto, currentUser, ruleConfigJson);
                whitedRuleConfigPO.setGmtModified(new Date());
                whitedRuleConfigMapper.updateByPrimaryKeySelective(whitedRuleConfigPO);
                return whitedRuleConfigPO.getId();
            } else {
                throw new RuntimeException("whitedRuleConfigPO id: " + dto.getId() + "Does not exist");
            }
        }

        tenantWhitedConfigContextV2.clearAllCache();
        buildWhitedRuleConfigPO(whitedRuleConfigPO, dto, currentUser, ruleConfigJson);
        whitedRuleConfigPO.setEnable(1);
        int insertResult = whitedRuleConfigMapper.insertSelective(whitedRuleConfigPO);
        if (insertResult > 0 && dto.getEnable() == 1 && WhitedRuleTypeEnum.RULE_ENGINE.name().equals(dto.getRuleType()) && !StringUtils.isEmpty(dto.getRiskRuleCode())) {
            //触发风险扫描
            RulePO rulePO = ruleMapper.findOne(dto.getRiskRuleCode());
            executorService.execute(() -> {
                scanService.scanByRule(rulePO.getId());
            });
        }
        return whitedRuleConfigPO.getId();
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

        Long globalTenantId = tenantRepository.findGlobalTenant().getId();
        Long userTenantId = UserInfoContext.getCurrentUser().getUserTenantId();
        if (!globalTenantId.equals(userTenantId)) {
            dto.setTenantIdList(Stream.of(userTenantId).toList());
        }

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
        if (Objects.nonNull(user)) {
            vo.setCreatorName(user.getUsername());
        }

        TenantPO tenantPO = tenantMapper.selectByPrimaryKey(whitedRuleConfigPO.getTenantId());
        if (Objects.nonNull(tenantPO)) {
            vo.setTenantName(tenantPO.getTenantName());
        }

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
        permissionCheck(id);

        WhitedRuleConfigPO whitedRuleConfigPO = whitedRuleConfigMapper.selectByPrimaryKey(id);
        if (Objects.isNull(whitedRuleConfigPO)) {
            throw new RuntimeException("The current whitelist does not exist");
        }
        UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
        if (!currentUser.getUserId().equals(whitedRuleConfigPO.getLockHolder())) {
            log.error("deleteById whitedRuleConfig error, lockHolder and current user different， whitedRuleid: {} , lockHolder:{}， currentUser:{} ", whitedRuleConfigPO.getId(), whitedRuleConfigPO.getLockHolder(), currentUser.getUserId());
            throw new RuntimeException("The current whitelist has been locked by other users, please grab the lock and try again!");
        }
        tenantWhitedConfigContextV2.clearAllCache();
        return whitedRuleConfigMapper.deleteByPrimaryKey(id);
    }

    @Override
    public void changeStatus(Long id, int enable) {
        permissionCheck(id);
        WhitedRuleConfigPO whitedRuleConfigPO = whitedRuleConfigMapper.selectByPrimaryKey(id);
        if (Objects.nonNull(whitedRuleConfigPO)) {
            UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
            if (!currentUser.getUserId().equals(whitedRuleConfigPO.getLockHolder())) {
                log.error("deleteById whitedRuleConfig error, lockHolder and current user different， whitedRuleid: {} , lockHolder:{}， currentUser:{} ", whitedRuleConfigPO.getId(), whitedRuleConfigPO.getLockHolder(), currentUser.getUserId());
                throw new RuntimeException("The current whitelist has been locked by other users, please grab the lock and try again!");
            }
            whitedRuleConfigPO.setEnable(enable);
            whitedRuleConfigPO.setGmtModified(new Date());
            tenantWhitedConfigContextV2.clearAllCache();
            whitedRuleConfigMapper.updateByPrimaryKeySelective(whitedRuleConfigPO);
        } else {
            throw new RuntimeException("whitedRuleConfigPO id: " + id + "Does not exist");
        }
    }


    @Override
    public void grabLock(Long id) {
        permissionCheck(id);
        WhitedRuleConfigPO whitedRuleConfigPO = whitedRuleConfigMapper.selectByPrimaryKey(id);
        if (Objects.nonNull(whitedRuleConfigPO)) {
            whitedRuleConfigPO.setLockHolder(UserInfoContext.getCurrentUser().getUserId());
            whitedRuleConfigPO.setGmtModified(new Date());
            whitedRuleConfigMapper.updateByPrimaryKeySelective(whitedRuleConfigPO);
        } else {
            throw new RuntimeException("whitedRuleConfigPO id: " + id + "Does not exist");
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
        queryScanResultDTO.setStatusList(Arrays.asList(RiskStatusManager.RiskStatus.UNREPAIRED.name(), RiskStatusManager.RiskStatus.WHITED.name()));
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
        List<RuleScanResultPO> listWithScrollId;
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

        return TestRunWhitedRuleResultDTO.builder()
                .count(count)
                .ruleScanResultList(preWhitedList)
                .build();
    }

    @Override
    public SaveWhitedRuleRequest queryWhitedContentByRisk(Long riskId) {
        ApiResponse<RuleScanResultVO> ruleScanResultVOApiResponse = riskService.queryRiskDetail(riskId);
        if (!StringUtils.isEmpty(ruleScanResultVOApiResponse.getErrorCode()) || Objects.isNull(ruleScanResultVOApiResponse.getContent())) {
            log.error("query RuleScanResultVO not exist,riskId:{} ", riskId);
            return null;
        }
        return buildContentByRiskInfo(ruleScanResultVOApiResponse.getContent());
    }

    @Override
    public ListVO<GroupByRuleCodeVO> getListGroupByRuleCode(QueryWhitedRuleDTO dto) {
        ListVO<GroupByRuleCodeVO> listVO = new ListVO<>();

        // Tenant isolation
        Long globalTenantId = tenantRepository.findGlobalTenant().getId();
        Long userTenantId = UserInfoContext.getCurrentUser().getUserTenantId();
        if (!globalTenantId.equals(userTenantId)) {
            dto.setTenantIdList(Stream.of(userTenantId).toList());
        }

        List<GroupByRuleCodeDTO> list = whitedRuleConfigMapper.findListGroupByRuleCode(dto);

        if (CollectionUtils.isEmpty(dto.getRuleCodeList())) {
            GroupByRuleCodeDTO groupByRuleCodeDTO = whitedRuleConfigMapper.findNullRuleCode(dto);
            if (Objects.nonNull(groupByRuleCodeDTO)) {
                list.add(0, groupByRuleCodeDTO);
            }
        }

        List<GroupByRuleCodeVO> result = list.stream()
                .skip((long) (dto.getPage() - 1) * dto.getSize())
                .limit(dto.getSize())
                .map(GroupByRuleCodeVO::build)
                .toList();

        listVO.setTotal(list.size());
        listVO.setData(result);

        return listVO;
    }

    private SaveWhitedRuleRequest buildContentByRiskInfo(RuleScanResultVO ruleScanResultVO) {
        RuleVO ruleVO = ruleScanResultVO.getRuleVO();
        SaveWhitedRuleRequest saveWhitedRuleRequest = new SaveWhitedRuleRequest();
        saveWhitedRuleRequest.setRuleName(ruleVO.getRuleName() + "_手动加白");
        saveWhitedRuleRequest.setRuleDesc(ruleVO.getRuleName() + "_手动加白");
        saveWhitedRuleRequest.setRuleType(WhitedRuleTypeEnum.RULE_ENGINE.name());
        saveWhitedRuleRequest.setRiskRuleCode(ruleScanResultVO.getRuleCode());

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
        saveWhitedRuleRequest.setCondition(condition.toString());
        saveWhitedRuleRequest.setRuleConfigList(ruleConfigList);
        return saveWhitedRuleRequest;
    }

    private void testRunParamCheck(TestRunWhitedRuleRequestDTO dto) {
        if (WhitedRuleTypeEnum.REGO.name().equals(dto.getRuleType()) && StringUtils.isEmpty(dto.getRegoContent())) {
            throw new RuntimeException("REGO whitelist content is empty");
        }
        if (!WhitedRuleTypeEnum.exist(dto.getRuleType())) {
            throw new RuntimeException("The whitelist type does not exist");
        }
        if (WhitedRuleTypeEnum.RULE_ENGINE.name().equals(dto.getRuleType())) {
            if (!CollectionUtils.isEmpty(dto.getRuleConfigList()) && dto.getRuleConfigList().size() == 1 && StringUtils.isEmpty(dto.getCondition())) {
                dto.setCondition("1");
            }
            if (!CollectionUtils.isEmpty(dto.getRuleConfigList()) && dto.getRuleConfigList().size() > 1 && StringUtils.isEmpty(dto.getCondition())) {
                throw new RuntimeException("There are multiple conditional configuration rules, please set their logical relationship!");
            }
        }
    }

    private void permissionCheck(Long whiteId) {
        if (whiteId != null) {
            WhitedRuleConfigPO whitedRuleConfigPO = whitedRuleConfigMapper.selectByPrimaryKey(whiteId);
            if (whitedRuleConfigPO != null) {
                Long tenantId = whitedRuleConfigPO.getTenantId();
                if (tenantId != null && !tenantId.equals(UserInfoContext.getCurrentUser().getUserTenantId())) {
                    throw new BizException("No permission to operate the whitelist,tenant not match");
                }
            }
        }
    }

    private void paramCheck(SaveWhitedRuleRequest dto, UserInfoDTO userInfo) {
        if (Objects.isNull(userInfo) || StringUtils.isEmpty(userInfo.getUserId())) {
            throw new RuntimeException("User information is empty");
        }
        if (!WhitedRuleTypeEnum.exist(dto.getRuleType())) {
            throw new RuntimeException("The whitelist type does not exist");
        }
        if (WhitedRuleTypeEnum.REGO.name().equals(dto.getRuleType()) && StringUtils.isEmpty(dto.getRegoContent())) {
            throw new RuntimeException("The content of the REGO whitelist is empty");
        }
        if (WhitedRuleTypeEnum.RULE_ENGINE.name().equals(dto.getRuleType())) {
            if (CollectionUtils.isEmpty(dto.getRuleConfigList())) {
                throw new RuntimeException("The whitelist is configured as empty");
            }
            if (dto.getRuleConfigList().size() > 1 && StringUtils.isEmpty(dto.getCondition())) {
                throw new RuntimeException("There are multiple conditional configuration rules, please set their logical relationship!");
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
                throw new RuntimeException("The current whitelist name already exists");
            }
        }
    }

    private void buildWhitedRuleConfigPO(WhitedRuleConfigPO whitedRuleConfigPO, SaveWhitedRuleRequest dto, UserInfoDTO userInfo, String ruleConfigJson) {
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
        whitedRuleConfigPO.setTenantId(userInfo.getUserTenantId());
        whitedRuleConfigPO.setRiskRuleCode(dto.getRiskRuleCode());
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
}

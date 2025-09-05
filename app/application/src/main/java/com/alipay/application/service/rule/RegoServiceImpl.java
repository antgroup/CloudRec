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

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alipay.application.service.common.RunningProgress;
import com.alipay.application.service.common.RunningProgressServiceImpl;
import com.alipay.application.service.common.utils.ThreadPoolConfig;
import com.alipay.application.service.resource.IQueryResource;
import com.alipay.application.service.resource.task.ResourceMergerTask;
import com.alipay.application.service.rule.domain.repo.OpaRepository;
import com.alipay.application.service.rule.utils.RegoCmdExecutorUtils;
import com.alipay.application.share.request.rule.*;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleRegoVO;
import com.alipay.application.share.vo.rule.TestRegoVO;
import com.alipay.common.constant.OpaFlagConstants;
import com.alipay.common.constant.TenantConstants;
import com.alipay.common.enums.TestRegoType;
import com.alipay.common.exception.BizException;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/*
 *@title RegoServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/6 10:04
 */
@Slf4j
@Service
public class RegoServiceImpl implements RegoService {

    @Resource
    private RuleRegoMapper ruleRegoMapper;
    @Resource
    private OpaRepository opaRepository;
    @Resource
    private RuleMapper ruleMapper;
    @Resource
    private GlobalVariableConfigMapper globalVariableConfigMapper;
    @Resource
    private CloudAccountMapper cloudAccountMapper;
    @Resource
    private IQueryResource iQueryResource;
    @Resource
    private TenantMapper tenantMapper;
    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;
    @Resource
    private RunningProgressServiceImpl runningProgressService;
    @Resource
    private ThreadPoolConfig threadPoolConfig;

    @Override
    public void saveRego(RegoRequest request) {
        RuleRegoPO ruleRegoPO = new RuleRegoPO();
        BeanUtils.copyProperties(request, ruleRegoPO);
        ruleRegoPO.setUserId(UserInfoContext.getCurrentUser().getUserId());

        RulePO rulePO = ruleMapper.selectByPrimaryKey(request.getRuleId());
        if (rulePO == null) {
            throw new BizException("The relevant rules do not exist");
        }

        String regoPackage = opaRepository.findPackage(request.getRuleRego());
        ruleRegoPO.setRegoPackage(regoPackage);
        ruleRegoPO.setPlatform(rulePO.getPlatform());
        ruleRegoPO.setResourceType(rulePO.getResourceType());

        RuleRegoPO existPO = ruleRegoMapper.findLatestOne(request.getRuleId());
        if (existPO != null) {
            // Compare whether the two versions are consistent, and there is no need to save the exact same situation.
            if (!Objects.equals(existPO.getRuleRego(), request.getRuleRego())) {
                ruleRegoPO.setVersion(existPO.getVersion() + 1);
                ruleRegoMapper.insertSelective(ruleRegoPO);
            }
        } else {
            ruleRegoPO.setVersion(1);
            ruleRegoMapper.insertSelective(ruleRegoPO);
        }
    }

    /**
     * Query the rego list, and the last 10 items are returned by default
     */
    @Override
    public ApiResponse<ListVO<RuleRegoVO>> queryRegoList(QueryRegoListRequest request) {
        ListVO<RuleRegoVO> listVO = new ListVO<>();
        int count = ruleRegoMapper.findCount(request.getRuleId());
        if (count == 0) {
            return new ApiResponse<>(listVO);
        }

        List<RuleRegoPO> list = ruleRegoMapper.findList(request.getRuleId(), request.getSize(),
                (request.getPage() - 1) * request.getSize());
        List<RuleRegoVO> collect = list.stream().map(RuleRegoVO::build).collect(Collectors.toList());

        listVO.setTotal(count);
        listVO.setData(collect);

        return new ApiResponse<>(listVO);
    }

    @Override
    public synchronized ApiResponse<TestRegoVO> testRego(TestRuleRequest req) {
        TestRegoVO testRegoVO = new TestRegoVO();
        String errorMsg = opaRepository.createOrUpdatePolicy(req.getRuleRego());
        if (errorMsg != null) {
            testRegoVO.setResult(errorMsg);
            return new ApiResponse<>(ApiResponse.FAIL.getCode(), testRegoVO);
        }

        updateGlobalVariableData(req.getGlobalVariableConfigIdList());

        if (StringUtils.isNotBlank(req.getType())) {
            // 租户级别
            if (TestRegoType.tenant.getType().equals(req.getType())) {
                Long taskId = runTenantRegoTestTask(req.getLinkedDataList(), req.getPlatform(), Long.valueOf(req.getSelectId()), req.getResourceType(), req.getRuleRego());
                testRegoVO.setTaskId(taskId);
            }

            // 账号级别
            if (TestRegoType.cloud_account.getType().equals(req.getType())) {
                Long taskId = runCloudAccountTestRegoTask(req.getLinkedDataList(), req.getPlatform(), req.getSelectId(), req.getResourceType(), req.getRuleRego());
                testRegoVO.setTaskId(taskId);
            }
        } else {
            // 示例数据
            Map<String, Object> result = executeRego(req.getRuleRego(), req.getInput());
            testRegoVO.setResult(result);
        }

        return new ApiResponse<>(testRegoVO);
    }

    @Override
    public Map<String, Object> executeRego(String rego, String input) {
        Map<String, Object> map = opaRepository.callOpa(rego, input);
        Object risk = map.get(OpaFlagConstants.RISK_MARKING);
        if (risk == null) {
            Map<String, Object> res = new HashMap<>();
            res.put("errors", "[risk] judgment identifier not included");
            return res;
        }

        return map;
    }


    /**
     * Asynchronously execute account execution rego policy
     *
     * @param platform       platform
     * @param cloudAccountId cloudAccountId
     * @param resourceType   resourceType
     * @param rego           rego
     * @return task ID
     */
    private Long runCloudAccountTestRegoTask(List<LinkDataParam> linkDataList, String platform, String cloudAccountId, String resourceType, String rego) {
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(cloudAccountId);
        if (cloudAccountPO != null) {
            Long taskId = runningProgressService.init(1);
            executeTestTasksAsynchronously(List.of(cloudAccountPO.getCloudAccountId()), platform, resourceType, rego, taskId, linkDataList);
            return taskId;
        }

        throw new BizException("云账号不存在");
    }


    public void refresh(int index, int total, Long taskId) {
        if (index != total - 1 && index != 0 && index % 5 == 0) {
            RunningProgress runningProgress = runningProgressService.update(taskId, index + 1, null);
            if (runningProgress.isCancel()) {
                throw new RuntimeException("任务取消");
            }
        } else {
            runningProgressService.update(taskId, index + 1, null);
        }
    }


    /**
     * Execute account execution rego strategy
     *
     * @param platform       platform
     * @param cloudAccountId cloudAccountId
     * @param resourceType   resourceType
     * @param rego           rego
     * @return result
     */
    private List<Map<String, Object>> runCloudAccountTestRegoTaskWhitResult(List<LinkDataParam> linkDataList, String platform, String cloudAccountId, String resourceType, String rego) {
        List<CloudResourceInstancePO> cloudResourceInstancePOS = iQueryResource.queryByCond(platform, resourceType, cloudAccountId);
        cloudResourceInstancePOS = ResourceMergerTask.mergeJson(linkDataList, cloudResourceInstancePOS, cloudAccountId);
        List<Map<String, Object>> results = new ArrayList<>();
        for (CloudResourceInstancePO cloudResourceInstancePO : cloudResourceInstancePOS) {
            Map<String, Object> result = executeRego(rego, cloudResourceInstancePO.getInstance());
            results.add(result);
        }
        return results;
    }

    /**
     * Execute account execution rego strategy
     *
     * @param platform     platform
     * @param resourceType resourceType
     * @param rego         rego
     * @return task ID
     */
    private Long runTenantRegoTestTask(List<LinkDataParam> linkDataList, String platform, Long tenantId, String resourceType, String rego) {
        TenantPO tenantPO = tenantMapper.selectByPrimaryKey(tenantId);
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().platform(platform).build();
        if (!TenantConstants.GLOBAL_TENANT.equals(tenantPO.getTenantName())) {
            cloudAccountDTO.setTenantId(tenantId);
        }
        List<String> allCloudAccountIdList = cloudResourceInstanceMapper.findAccountList(platform, resourceType);
        List<CloudAccountPO> cloudAccountPOList = cloudAccountMapper.findList(cloudAccountDTO);
        List<String> tenantCloudAccountIdList = cloudAccountPOList.stream().map(CloudAccountPO::getCloudAccountId).toList();
        tenantCloudAccountIdList = tenantCloudAccountIdList.stream().filter(allCloudAccountIdList::contains).toList();


        Long taskId = runningProgressService.init(tenantCloudAccountIdList.size());
        executeTestTasksAsynchronously(tenantCloudAccountIdList, platform, resourceType, rego, taskId, linkDataList);
        return taskId;
    }

    private static final int MAX_RESULT_SIZE = 20;

    /**
     * 异步执行测试任务
     *
     * @param cloudAccountIdList 账号列表
     * @param platform           平台
     * @param resourceType       资源类型
     * @param rego               策略
     * @param taskId             任务id
     * @param linkDataList       关联数据
     */
    private void executeTestTasksAsynchronously(List<String> cloudAccountIdList, String platform, String resourceType, String rego, Long taskId, List<LinkDataParam> linkDataList) {
        int allAccountSize = cloudAccountIdList.size();
        // results 最多保留100条记录，超出部分不展示，避免数据量过大导致前端卡死 && 避免OOM
        log.info("executeTestTasksAsynchronously start, taskId:{}, cloudAccountPOList.size:{} platform:{} resourceType:{}", taskId, allAccountSize, platform, resourceType);
        List<Map<String, Object>> results = new ArrayList<>();
        AtomicInteger total = new AtomicInteger();
        AtomicInteger riskCount = new AtomicInteger();
        threadPoolConfig.asyncServiceExecutor().execute(() -> {
            for (int i = 0; i < cloudAccountIdList.size(); i++) {
                try {
                    List<Map<String, Object>> result = runCloudAccountTestRegoTaskWhitResult(linkDataList, platform, cloudAccountIdList.get(i), resourceType, rego);
                    for (Map<String, Object> map : result) {
                        boolean risk = (boolean) map.get(OpaFlagConstants.RISK_MARKING);
                        if (risk) {
                            riskCount.getAndIncrement();
                        }
                        if (riskCount.get() <= MAX_RESULT_SIZE) {
                            results.add(map);
                        }
                    }
                    total.addAndGet(result.size());
                } catch (Exception e) {
                    log.error("executeTestTasksAsynchronously error, cloudAccountId:{}, platform:{}, resourceType:{}", cloudAccountIdList.get(i), platform, resourceType, e);
                } finally {
                    refresh(i, allAccountSize, taskId);
                }
            }

            LinkedHashMap<Object, Object> message = new LinkedHashMap<>();
            message.put("Total", total);
            message.put("RiskCount", riskCount);
            message.put("Result", results.stream().limit(MAX_RESULT_SIZE).toList());
            String msg = JSON.toJSONString(message, SerializerFeature.WriteMapNullValue);
            runningProgressService.update(taskId, allAccountSize, msg);
        });
    }

    @Override
    public ApiResponse<RegoCmdExecutorUtils.RegoCmdExecutorResponse> lintRego(LintRegoRequest lintRegoRequest) {
        RegoCmdExecutorUtils.RegoCmdExecutorResponse regoCmdExecutorResponse = RegoCmdExecutorUtils
                .executeRegoCmd(lintRegoRequest.getRuleRego());
        return new ApiResponse<>(regoCmdExecutorResponse);
    }


    public void updateGlobalVariableData(List<Long> globalVariableConfigIdList) {
        if (!CollectionUtils.isEmpty(globalVariableConfigIdList)) {
            for (Long globalVariableConfigId : globalVariableConfigIdList) {
                GlobalVariableConfigPO globalVariableConfigPO = globalVariableConfigMapper
                        .selectByPrimaryKey(globalVariableConfigId);
                if (globalVariableConfigPO != null) {
                    opaRepository.upsertData(globalVariableConfigPO.getPath(),
                            JSON.parse(globalVariableConfigPO.getData()));
                }
            }
        }
    }
}

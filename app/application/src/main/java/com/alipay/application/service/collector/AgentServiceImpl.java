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
package com.alipay.application.service.collector;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alipay.application.service.collector.domain.Agent;
import com.alipay.application.service.collector.domain.CollectRecordInfo;
import com.alipay.application.service.collector.domain.TaskResp;
import com.alipay.application.service.collector.domain.repo.AgentRepository;
import com.alipay.application.service.collector.domain.repo.CollectorTaskRepository;
import com.alipay.application.service.collector.enums.TaskStatus;
import com.alipay.application.service.common.Platform;
import com.alipay.application.service.common.utils.DBDistributedLockUtil;
import com.alipay.application.service.common.utils.ThreadPoolConfig;
import com.alipay.application.service.resource.DelResourceService;
import com.alipay.application.service.resource.job.ClearJob;
import com.alipay.application.service.rule.job.AccountScanJob;
import com.alipay.application.service.system.utils.TokenUtil;
import com.alipay.application.share.request.collector.AcceptSupportResourceTypeRequest;
import com.alipay.application.share.request.collector.LogRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.collector.AgentCloudAccountVO;
import com.alipay.application.share.vo.collector.AgentRegistryVO;
import com.alipay.application.share.vo.collector.OnceTokenVO;
import com.alipay.application.share.vo.collector.Registry;
import com.alipay.common.enums.PlatformType;
import com.alipay.common.enums.Status;
import com.alipay.common.exception.BizException;
import com.alipay.common.utils.DateUtil;
import com.alipay.common.utils.ListUtils;
import com.alipay.dao.dto.AgentRegistryDTO;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.dto.CollectorRecordDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/*
 *@title AgentServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/8/13 14:20
 */

@Slf4j
@Service
public class AgentServiceImpl implements AgentService {

    /**
     * Maximum number of accounts per collector
     */
    private static final Integer MAX_ACCOUNT_COUNT = 50;

    @Resource
    private AgentRegistryMapper agentRegistryMapper;
    @Resource
    private AgentRepository agentRepository;
    @Resource
    private AgentRegistryTokenMapper agentRegistryTokenMapper;
    @Resource
    private UserMapper userMapper;
    @Resource
    private CloudAccountMapper cloudAccountMapper;
    @Resource
    private ResourceMapper resourceMapper;
    @Resource
    private PlatformMapper platformMapper;
    @Resource
    private AgentRegistryCloudAccountMapper agentRegistryCloudAccountMapper;
    @Resource
    private ClearJob clearJob;
    @Resource
    private AccountScanJob accountScanJob;
    @Resource
    private DelResourceService delResourceService;
    @Resource
    private CollectorRecordMapper collectorRecordMapper;
    @Resource
    private CollectorTaskRepository collectorTaskRepository;
    @Resource
    private CollectorTaskMapper collectorTaskMapper;
    @Resource
    private CollectorLogMapper collectorLogMapper;
    @Resource
    private ThreadPoolConfig threadPoolConfig;
    @Resource
    private DBDistributedLockUtil dbDistributedLockUtil;

    @Value("${collector.bucket.url}")
    private String bucketUrl;

    @Value("${server.url}")
    private String serverUrl;

    @Override
    public ApiResponse<Registry.RegistryResponse> registry(Registry registry, String onceToken) {
        Registry.RegistryResponse registryResponse = new Registry.RegistryResponse();

        Agent agent = agentRepository.find(registry.getPlatform(), registry.getRegistryValue());

        if (agent != null && Status.exit.name().equals(agent.getStatus())) {
            registryResponse.setStatus(agent.getStatus());
            return new ApiResponse<>(registryResponse);
        }

        if (agent == null) {
            agent = Agent.newAgent(registry.getPlatform(), registry.getRegistryValue(), registry.getCron(),
                    registry.getAgentName(), registry.getSecretKey(), onceToken, JSON.toJSONString(registry.getHealthStatus()));
            agentRepository.save(agent);
        } else {
            agent.refreshAgent(registry.getOnceToken(), registry.getSecretKey(), JSON.toJSONString(registry.getHealthStatus()));
            agentRepository.save(agent);
        }
        registryResponse.setPersistentToken(agent.getPersistentToken());
        registryResponse.setStatus(agent.getStatus());

        AgentRegistryTokenPO agentRegistryTokenPO = agentRegistryTokenMapper.findOne(onceToken);
        if (agentRegistryTokenPO != null) {
            agentRegistryTokenPO.setUsed(1);
            agentRegistryTokenMapper.updateByPrimaryKeySelective(agentRegistryTokenPO);
        }

        return new ApiResponse<>(registryResponse);
    }

    /**
     * Query agent list with memory-based pagination
     * This method retrieves all matching agents and performs pagination in memory
     * 
     * @param dto the agent registry query parameters
     * @return ApiResponse containing paginated agent list
     */
    @Override
    public ApiResponse<ListVO<AgentRegistryVO>> queryAgentList(AgentRegistryDTO dto) {
        ListVO<AgentRegistryVO> listVO = new ListVO<>();
        
        // Get all matching agents without database pagination
        AgentRegistryDTO queryDto = new AgentRegistryDTO();
        queryDto.setPlatform(dto.getPlatform());
        queryDto.setAgentName(dto.getAgentName());
        queryDto.setRegistryValue(dto.getRegistryValue());
        queryDto.setStatus(dto.getStatus());
        
        List<AgentRegistryPO> allAgents = agentRegistryMapper.findAggList(queryDto);
        
        if (allAgents.isEmpty()) {
            return new ApiResponse<>(listVO);
        }
        
        // Memory-based pagination using utility method
        ListUtils.PaginationResult<AgentRegistryPO> paginationResult = ListUtils.paginate(allAgents, dto.getPage(), dto.getSize());
        List<AgentRegistryPO> pagedAgents = paginationResult.getData();
        List<AgentRegistryVO> collect = pagedAgents.stream().map(AgentRegistryVO::build).toList();
        
        listVO.setData(collect);
        listVO.setTotal(paginationResult.getTotal());
        
        return new ApiResponse<>(listVO);
    }

    @Override
    public OnceTokenVO getOnceToken(String userId) {
        UserPO userPO = userMapper.findOne(userId);
        if (userPO == null) {
            throw new BizException("User does not exist");
        }

        // check whether there are unused temporary tokens
        AgentRegistryTokenPO existPO = agentRegistryTokenMapper.findNotUsedToken(userId);
        if (existPO != null) {
            // check expiration time
            if (existPO.getOnceTokenExpireTime().getTime() > System.currentTimeMillis()) {
                return getOnceTokenResult(userPO, existPO);
            } else {
                agentRegistryTokenMapper.deleteByPrimaryKey(existPO.getId());
            }
        }

        // create a token and expire in one day
        long expireTime = 60 * 60 * 1000 * 24;
        AgentRegistryTokenPO agentRegistryTokenPO = new AgentRegistryTokenPO();
        agentRegistryTokenPO.setUserId(userId);
        agentRegistryTokenPO.setUsed(0);
        String sign = TokenUtil.sign(userPO.getUserId(), userPO.getUsername(), expireTime);
        agentRegistryTokenPO.setOnceToken(sign);
        agentRegistryTokenPO.setOnceTokenCreateTime(new Date());
        // Set expiration time current time +1h
        agentRegistryTokenPO.setOnceTokenExpireTime(new Date(System.currentTimeMillis() + expireTime));
        agentRegistryTokenMapper.insertSelective(agentRegistryTokenPO);

        return getOnceTokenResult(userPO, agentRegistryTokenPO);
    }

    @Override
    public void checkOnceToken(Registry registry, String token) {
        // not exist
        AgentRegistryTokenPO agentRegistryTokenPO = agentRegistryTokenMapper.findOne(token);
        if (agentRegistryTokenPO == null) {
            throw new IllegalArgumentException(
                    "The accessToken does not exist. Please go to the web console to obtain the latest accessToken.");
        }

        // Check if the token is expired
        if (agentRegistryTokenPO.getOnceTokenExpireTime().before(new Date())) {
            AgentRegistryPO agentRegistryPO = agentRegistryMapper.findOne(registry.getPlatform(), registry.getRegistryValue());
            if (agentRegistryPO == null) {
                throw new IllegalArgumentException(
                        "The accessToken has expired. Please go to the web console to generate a new accessToken.");
            }
        }


        // Check if the token is used
        if (agentRegistryTokenPO.getUsed() == 1) {
            boolean find = false;
            List<AgentRegistryPO> agentRegistryPOList = agentRegistryMapper.findAll();
            if (!agentRegistryPOList.isEmpty()) {
                for (AgentRegistryPO agentRegistryPO : agentRegistryPOList) {
                    if (agentRegistryPO.getRegistryValue().equals(registry.getRegistryValue())) {
                        if (agentRegistryPO.getOnceToken().equals(token)) {
                            find = true;
                            break;
                        }
                    }
                }
            }

            if (!find) {
                throw new IllegalArgumentException(
                        "The accessToken has been used. Please go to the web console to generate a new accessToken.");
            }
        }
    }

    @Override
    public AgentRegistryPO checkPersistentToken(String platform, String registryValue, String token) {
        Registry registry = new Registry();
        registry.setPlatform(platform);
        registry.setRegistryValue(registryValue);
        AgentRegistryPO agentRegistryPO = agentRegistryMapper.findOne(registry.getPlatform(), registry.getRegistryValue());
        if (agentRegistryPO == null) {
            throw new IllegalArgumentException("persistentToken exception");
        }

        // Check whether the persistent token meets expectations
        if (!token.equals(agentRegistryPO.getPersistentToken())) {
            throw new RuntimeException("persistentToken exception");
        }

        return agentRegistryPO;
    }

    @NotNull
    private OnceTokenVO getOnceTokenResult(UserPO userPO, AgentRegistryTokenPO existPO) {
        List<OnceTokenVO> result = new ArrayList<>();

        // alibaba account
        String scriptTemplate = "curl -L -o %s.tar.gz %s/%s.tar.gz && tar -xzf %s.tar.gz && cd %s && nohup ./%s --serverUrl \"%s\" --accessToken \"%s\" > /dev/null 2>&1 &";
        String alicloudScript = parseScript(scriptTemplate, "deploy_alicloud", "cloudrec_collector_alicloud", bucketUrl, serverUrl, existPO.getOnceToken());
        result.add(createOnceToken(Platform.getPlatformName(PlatformType.ALI_CLOUD.getPlatform()), alicloudScript, userPO, existPO));

        // tencent account
        String tencentScript = parseScript(scriptTemplate, "deploy_tencent", "cloudrec_collector_tencent", bucketUrl, serverUrl, existPO.getOnceToken());
        result.add(createOnceToken(Platform.getPlatformName(PlatformType.TENCENT_CLOUD.getPlatform()), tencentScript, userPO, existPO));

        // huawei account
        String huaweiScript = parseScript(scriptTemplate, "deploy_hws", "cloudrec_collector_hws", bucketUrl, serverUrl, existPO.getOnceToken());
        result.add(createOnceToken(Platform.getPlatformName(PlatformType.HUAWEI_CLOUD.getPlatform()), huaweiScript, userPO, existPO));

        // aws
        String awsScript = parseScript(scriptTemplate, "deploy_aws", "cloudrec_collector_aws", bucketUrl, serverUrl, existPO.getOnceToken());
        result.add(createOnceToken(Platform.getPlatformName(PlatformType.AWS.getPlatform()), awsScript, userPO, existPO));

        // gcp
        String gcpScript = parseScript(scriptTemplate, "deploy_gcp", "cloudrec_collector_gcp", bucketUrl, serverUrl, existPO.getOnceToken());
        result.add(createOnceToken(Platform.getPlatformName(PlatformType.GCP.getPlatform()), gcpScript, userPO, existPO));

        // baidu account
        String baiduScript = parseScript(scriptTemplate, "deploy_baidu", "cloudrec_collector_badiu", bucketUrl, serverUrl, existPO.getOnceToken());
        result.add(createOnceToken(Platform.getPlatformName(PlatformType.BAIDU_CLOUD.getPlatform()), baiduScript, userPO, existPO));

        // huawei private account
        String hwsPrivateScript = parseScript(scriptTemplate, "deploy_hws_private", "cloudrec_collector_hws_private", bucketUrl, serverUrl, existPO.getOnceToken());
        result.add(createOnceToken(Platform.getPlatformName(PlatformType.HUAWEI_CLOUD_PRIVATE.getPlatform()), hwsPrivateScript, userPO, existPO));

        // ali private account
        String alibabCloudPrivateScript = parseScript(scriptTemplate, "deploy_alicloud_private", "cloudrec_collector_alicloud_private", bucketUrl, serverUrl, existPO.getOnceToken());
        result.add(createOnceToken(Platform.getPlatformName(PlatformType.ALI_CLOUD_PRIVATE.getPlatform()), alibabCloudPrivateScript, userPO, existPO));

        // all account platforms
        String cloudRecScript = parseScript(scriptTemplate, "deploy_cloudrec", "cloudrec_collector", bucketUrl, serverUrl, existPO.getOnceToken());
        List<String> platformList = Platform.getPlatformNameList(PlatformType.ALI_CLOUD, PlatformType.TENCENT_CLOUD,
                PlatformType.BAIDU_CLOUD, PlatformType.HUAWEI_CLOUD, PlatformType.TENCENT_CLOUD, PlatformType.BAIDU_CLOUD);
        result.add(createOnceToken(Strings.join(platformList, ','), cloudRecScript, userPO, existPO));

        OnceTokenVO onceToken = createOnceToken(Strings.join(platformList, ','), cloudRecScript, userPO, existPO);
        onceToken.setTokenList(result);
        return onceToken;
    }

    private String parseScript(String scriptTemplate, String zipName, String programName, String bucketUrl, String serverUrl, String accessToken) {
        return String.format(scriptTemplate, zipName, bucketUrl, zipName, zipName, zipName, programName, serverUrl, accessToken);
    }


    private OnceTokenVO createOnceToken(String platformName, String script, UserPO userPO, AgentRegistryTokenPO existPO) {
        OnceTokenVO onceTokenVO = new OnceTokenVO();
        onceTokenVO.setPlatformName(platformName);
        onceTokenVO.setToken(existPO.getOnceToken());
        onceTokenVO.setExpireTime(DateUtil.dateToString(existPO.getOnceTokenExpireTime(), "yyyy-MM-dd HH:mm:ss"));
        onceTokenVO.setScript(script);
        onceTokenVO.setUsername(userPO.getUsername());
        return onceTokenVO;
    }

    @Transactional(rollbackFor = RuntimeException.class)
    @Override
    public ApiResponse<List<AgentCloudAccountVO>> queryCloudAccountList(String persistentToken, String registryValue,
                                                                        String platform, List<String> sites, List<Long> taskIds, Integer freeCloudAccountCount) {

        String lockKey = "query::cloud::account:list";
        if (!dbDistributedLockUtil.tryLock(lockKey, 5 * 60)) {
            throw new BizException("Failed to acquire the lock");
        }

        try {
            // 1. check persistentToken
            AgentRegistryPO agentRegistryPO = checkPersistentToken(platform, registryValue, persistentToken);
            if (agentRegistryPO.getSecretKey() == null) {
                throw new RuntimeException(platform + ":" + registryValue + "SecretKey not exist");
            }

            // 2. check collector count
            AgentRegistryDTO agentRegistryDTO = new AgentRegistryDTO();
            agentRegistryDTO.setStatus(Status.valid.name());
            agentRegistryDTO.setPlatform(platform);
            List<AgentRegistryPO> collectorList = agentRegistryMapper.findList(agentRegistryDTO);
            if (collectorList.isEmpty()) {
                try {
                    Thread.sleep(10 * 1000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                collectorList = agentRegistryMapper.findList(agentRegistryDTO);
                if (collectorList.isEmpty()) {
                    throw new RuntimeException(platform + ":" + registryValue + "Abnormal heartbeat");
                }
            }

            // 3. get task account
            List<CloudAccountPO> list = new ArrayList<>();
            if (CollectionUtils.isNotEmpty(taskIds)) {
                List<CollectorTaskPO> collectorTaskPOList = collectorTaskMapper.findByIds(taskIds);
                // Obtain it preferentially from the collection task table
                if (CollectionUtils.isNotEmpty(collectorTaskPOList)) {
                    list = collectorTaskPOList.stream()
                            // Avoid being preempted by other collectors, causing tasks to run multiple times
                            .filter(po -> po.getRegistryValue().equals(registryValue))
                            .map(po -> cloudAccountMapper.findByCloudAccountId(po.getCloudAccountId()))
                            .toList();
                    collectorTaskRepository.updateTaskStatus(taskIds, TaskStatus.running.name());
                }
            } else {
                // Get the number of accounts to be executed based on the currently surviving collector
                list = cloudAccountMapper.findNotRunningAccount(platform, sites);
                if (list.isEmpty()) {
                    throw new RuntimeException(platform + ":" + registryValue
                            + "The account accounts of the current platform are all in operation and account accounts cannot be allocated");
                }

                if (collectorList.isEmpty()) {
                    throw new RuntimeException(platform + ":" + registryValue + "There is currently no collector running");
                }

                // Apply freeCloudAccountCount limit if specified
                int accountLimit = MAX_ACCOUNT_COUNT;
                if (freeCloudAccountCount != null && freeCloudAccountCount > 0) {
                    accountLimit = Math.min(freeCloudAccountCount, MAX_ACCOUNT_COUNT);
                }

                if (collectorList.size() != 1 && list.size() > collectorList.size()) {
                    list = list.stream().limit(Math.min(list.size() / collectorList.size(), accountLimit)).toList();
                } else {
                    list = list.stream().limit(accountLimit).toList();
                }
            }

            // 4. build result
            List<AgentCloudAccountVO> collect = list.stream()
                    .filter(po -> StringUtils.isNotBlank(po.getCredentialsJson()))
                    .map(po -> {
                        try {
                            return AgentCloudAccountVO.build(po, agentRegistryPO);
                        } catch (Exception e) {
                            log.error("build AgentCloudAccountVO error,cloudAccountId:{}", po.getCloudAccountId(), e);
                            return null;
                        }
                    }).filter(Objects::nonNull).toList();

            // 5. pre handler
            accountLockCollectPreHandler(list);

            return new ApiResponse<>(collect);
        } catch (Exception e) {
            log.error("queryCloudAccountList error", e);
        } finally {
            dbDistributedLockUtil.releaseLock(lockKey);
        }

        throw new BizException("Failed to obtain cloud account, server exception");
    }


    /**
     * Change the cloud account collection account to running to prevent other collectors from preempting
     * @param list cloud account list
     */
    private void accountLockCollectPreHandler(List<CloudAccountPO> list) {
        for (CloudAccountPO cloudAccountPO : list) {
            // TODO change inQueue status
            cloudAccountPO.setCollectorStatus(Status.running.name());
            cloudAccountMapper.updateByPrimaryKeySelective(cloudAccountPO);
        }
    }

    /**
     * The account actually starts running, modify the account status and pre-delete asset data
     * @param list cloud account list
     * @param agentRegistryPO agent registry po
     */
    private void accountStartCollectPreHandler(List<CloudAccountPO> list, AgentRegistryPO agentRegistryPO) {
        log.info("accountStartCollectPreHandler start");
        for (CloudAccountPO cloudAccountPO : list) {
            log.info("accountStartCollectPreHandler cloudAccountId:{}", cloudAccountPO.getCloudAccountId());
            try {
                // Change the status of this batch of account accounts to running
                cloudAccountPO.setCollectorStatus(Status.running.name());
                cloudAccountPO.setLastScanTime(new Date());
                cloudAccountMapper.updateByPrimaryKeySelective(cloudAccountPO);

                // Bind the corresponding relationship between account and collector
                AgentRegistryCloudAccountPO agentRegistryCloudAccountPO = agentRegistryCloudAccountMapper
                        .findOne(agentRegistryPO.getId(), cloudAccountPO.getCloudAccountId());
                if (agentRegistryCloudAccountPO == null) {
                    agentRegistryCloudAccountPO = new AgentRegistryCloudAccountPO();
                    agentRegistryCloudAccountPO.setAgentRegistryId(agentRegistryPO.getId());
                    agentRegistryCloudAccountPO.setCloudAccountId(cloudAccountPO.getCloudAccountId());
                    agentRegistryCloudAccountPO.setRegistryValue(agentRegistryPO.getRegistryValue());
                    agentRegistryCloudAccountPO.setPlatform(agentRegistryPO.getPlatform());
                    try {
                        agentRegistryCloudAccountMapper.insertSelective(agentRegistryCloudAccountPO);
                    } catch (Exception e) {
                        log.error("Exceptions due to concurrent registrations");
                    }
                }

                // Pre-delete asset data
                int effectCount = delResourceService.preDeleteByCloudAccountId(cloudAccountPO.getCloudAccountId());
                log.info("accountStartCollectPreHandler delResourceService.preDeleteByCloudAccountId,cloudAccountId:{},effectCount:{}", cloudAccountPO.getCloudAccountId(), effectCount);
            } catch (Exception e) {
                log.error("accountStartCollectPreHandler error,cloudAccountId:{}", cloudAccountPO.getCloudAccountId(), e);
            }
            log.info("accountStartCollectPreHandler end,cloudAccountId:{}", cloudAccountPO.getCloudAccountId());
        }

        log.info("accountStartCollectPreHandler end");
    }


    @Override
    public void exitAgent(String onceToken) {
        List<AgentRegistryPO> agentRegistryPOList = agentRegistryMapper.findListByOnceToken(onceToken);
        for (AgentRegistryPO agentRegistryPO : agentRegistryPOList) {
            agentRegistryPO.setStatus(Status.exit.name());
            agentRegistryMapper.updateByPrimaryKeySelective(agentRegistryPO);
        }
    }

    @Override
    public void acceptSupportResourceType(AcceptSupportResourceTypeRequest request) {
        PlatformType platformType = PlatformType.getPlatformType(request.getPlatform());
        if (platformType == null) {
            throw new RuntimeException("Unsupported platform type, please add it on the server side");
        }

        // Create or update platform information
        int count = platformMapper.findOne(request.getPlatform());
        PlatformPO platformPO = new PlatformPO();
        platformPO.setPlatform(request.getPlatform());
        platformPO.setPlatformName(request.getPlatformName());
        if (count == 0) {
            platformMapper.insertSelective(platformPO);
        } else {
            platformMapper.updateByPrimaryKeySelective(platformPO);
        }


        for (AcceptSupportResourceTypeRequest.Resource resource : request.getResourceList()) {
            // Create or update an asset type
            ResourcePO existPO = resourceMapper.findOne(request.getPlatform(), resource.getResourceType());
            if (existPO == null) {
                ResourcePO resourcePO = new ResourcePO();
                resourcePO.setResourceType(resource.getResourceType());
                resourcePO.setResourceName(resource.getResourceTypeName());
                resourcePO.setPlatform(request.getPlatform());
                resourcePO.setResourceGroupType(resource.getResourceGroupType());
                resourceMapper.insertSelective(resourcePO);
            } else {
                existPO.setResourceName(resource.getResourceTypeName());
                existPO.setResourceGroupType(resource.getResourceGroupType());
                resourceMapper.updateByPrimaryKeySelective(existPO);
            }
        }
    }


    public static Cache<String, Boolean> cache() {
        return CacheBuilder.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(60, TimeUnit.MINUTES)
                .build();
    }

    private final Lock lock = new ReentrantLock();

    public void log(LogRequest logRequest) {
        // During a period of time window, requests for the same key are processed only once.
        if (cache().getIfPresent(logRequest.getUniqueKey()) != null) {
            log.info("Log already exists, uniqueKey:{}", logRequest.getUniqueKey());
            return;
        }

        cache().put(logRequest.getUniqueKey(), true);

        lock.lock();
        try {
            CollectorLogPO collectorLogPO = collectorLogMapper.findByUniqueKey(logRequest.getUniqueKey());
            if (collectorLogPO == null) {
                collectorLogPO = new CollectorLogPO();
                collectorLogPO.setUniqueKey(logRequest.getUniqueKey());
                collectorLogPO.setLevel(logRequest.getLevel());
                collectorLogPO.setTime(logRequest.getTime());
                collectorLogPO.setPlatform(logRequest.getPlatform());
                collectorLogPO.setCloudAccountId(logRequest.getCloudAccountId());
                collectorLogPO.setResourceType(logRequest.getResourceType());
                collectorLogPO.setType(logRequest.getType());
                collectorLogPO.setMessage(logRequest.getMessage());
                collectorLogPO.setCollectorRecordId(logRequest.getCollectRecordId());
                collectorLogPO.setDescription(logRequest.getDescription());
                collectorLogMapper.insertSelective(collectorLogPO);
            } else {
                collectorLogPO.setTime(logRequest.getTime());
                collectorLogPO.setCollectorRecordId(logRequest.getCollectRecordId());
                collectorLogMapper.updateByPrimaryKeySelective(collectorLogPO);
            }
        } finally {
            lock.unlock();
        }
    }

    @Transactional(rollbackFor = RuntimeException.class)
    @Override
    public void runningStartSignal(String token, String cloudAccountId, CollectRecordInfo collectRecordInfo) {
        log.info("runningStartSignal, cloudAccountId:{}, collectRecordInfo:{}", cloudAccountId, collectRecordInfo);
        CollectorRecordPO collectorRecordPO = collectorRecordMapper.selectByPrimaryKey(collectRecordInfo.getCollectRecordId());
        if (collectorRecordPO != null) {
            collectorRecordPO.setStartTime(new Date());
            collectorRecordPO.setCollectRecordInfo(JSON.toJSONString(collectRecordInfo, SerializerFeature.WriteMapNullValue));
            collectorRecordMapper.updateByPrimaryKeySelective(collectorRecordPO);

            if (collectRecordInfo.getEnableCollection()) {
                CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(cloudAccountId);
                AgentRegistryPO agentRegistryPO = agentRegistryMapper.findOne(cloudAccountPO.getPlatform(), collectorRecordPO.getRegistryValue());
                CompletableFuture.runAsync(() -> accountStartCollectPreHandler(Collections.singletonList(cloudAccountPO), agentRegistryPO), threadPoolConfig.asyncServiceExecutor())
                        .exceptionally(e -> {
                            log.error("Error in accountStartCollectPreHandler", e);
                            return null;
                        });
            }
        }


    }

    @Transactional(rollbackFor = RuntimeException.class)
    @Override
    public void runningFinishSignal(String cloudAccountId, Long taskId) {
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(cloudAccountId);
        if (cloudAccountPO == null) {
            log.error("Cloud account not found, cloudAccountId:{}", cloudAccountId);
            return;
        }

        // Update cloud account collection status
        cloudAccountPO.setCollectorStatus(Status.waiting.name());
        cloudAccountPO.setLastScanTime(new Date());
        cloudAccountMapper.updateByPrimaryKeySelective(cloudAccountPO);

        // update collector record
        CollectorRecordPO collectorRecordPO = collectorRecordMapper.findLastOne(cloudAccountId);
        if (collectorRecordPO != null) {
            collectorRecordPO.setEndTime(new Date());
            collectorRecordMapper.updateByPrimaryKeySelective(collectorRecordPO);
        }

        // delete historical collect record
        CollectorRecordDTO collectorRecordDTO = CollectorRecordDTO.builder().cloudAccountId(cloudAccountId).build();
        List<CollectorRecordPO> list = collectorRecordMapper.findList(collectorRecordDTO);

        final int storeRecordCount = 10;
        // Only the last 10 records are retained
        if (list.size() > storeRecordCount) {
            list = list.stream().sorted(Comparator.comparing(CollectorRecordPO::getId).reversed()).skip(storeRecordCount).toList();
            for (CollectorRecordPO po : list) {
                collectorRecordMapper.deleteByPrimaryKey(po.getId());
                collectorLogMapper.deleteByRecordId(po.getId());
            }
        }

        // Modify task status
        if (taskId != null && taskId > 0) {
            collectorTaskRepository.updateTaskStatus(List.of(taskId), TaskStatus.done.name());
            log.info("Task status updated, taskId:{}", taskId);
        }

        log.info("Cloud account collection finished, cloudAccountId:{}", cloudAccountId);

        CollectorRecordPO lastOneCollectRecord = collectorRecordMapper.findLastOne(cloudAccountId);
        if (lastOneCollectRecord != null) {
            CollectRecordInfo collectRecordInfo = JSON.parseObject(lastOneCollectRecord.getCollectRecordInfo(), CollectRecordInfo.class);
            if (collectRecordInfo != null && collectRecordInfo.getEnableCollection()) {
                log.info("Delete historical version data or scan, cloudAccountId:{}", cloudAccountId);
                // Delayed tasks:Delete historical version data
                // Delete 10s to prevent data submission from not completing
                SchedulerManager.getScheduler().schedule(
                        () ->
                        {
                            try {
                                clearJob.commitDeleteResourceByCloudAccount(cloudAccountId);
                                accountScanJob.scanByCloudAccountId(cloudAccountId);
                            } catch (Exception e) {
                                log.error("Delete historical version data or scan failed, cloudAccountId:{}", cloudAccountId, e);
                            }
                        },
                        10,
                        TimeUnit.SECONDS
                );
            }
        }
    }


    /**
     * Agent health check
     */
    @Transactional(rollbackFor = Exception.class)
    @Override
    public void HealthCheck() {
        List<AgentRegistryPO> list = agentRegistryMapper
                .findListByStatusList(List.of(Status.valid.name(), Status.unusual.name(), Status.exit.name()));
        list.forEach(agentRegistryPO -> {

            if (agentRegistryPO.getStatus().equals(Status.exit.name())) {
                clear(agentRegistryPO.getId());
                return;
            }

            // If the patient is in a healthy state, a heartbeat of 1 minute will be changed to unhealthy.
            if (agentRegistryPO.getStatus().equals(Status.valid.name())) {
                if (System.currentTimeMillis() - agentRegistryPO.getRegistryTime().getTime() > 60 * 1000) {
                    agentRegistryPO.setStatus(Status.unusual.name());
                    agentRegistryMapper.updateByPrimaryKeySelective(agentRegistryPO);
                }
                return;
            }

            // Unhealthy, no heartbeat within 5 minutes will be changed to offline
            if (agentRegistryPO.getStatus().equals(Status.unusual.name())) {
                if (System.currentTimeMillis() - agentRegistryPO.getRegistryTime().getTime() > 5 * 60 * 1000) {
                    clear(agentRegistryPO.getId());
                }
            }
        });
    }

    private void clear(Long id) {
        agentRegistryMapper.deleteByPrimaryKey(id);
        List<AgentRegistryCloudAccountPO> agentRegistryCloudAccountPOList = agentRegistryCloudAccountMapper
                .findList(id);
        // Change the detection status of the corresponding account account to pending detection
        if (!agentRegistryCloudAccountPOList.isEmpty()) {
            for (AgentRegistryCloudAccountPO po : agentRegistryCloudAccountPOList) {
                agentRegistryCloudAccountMapper.deleteByPrimaryKey(po.getId());
                CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(po.getCloudAccountId());
                if (cloudAccountPO != null && Status.running.name().equals(cloudAccountPO.getCollectorStatus())) {
                    cloudAccountPO.setCollectorStatus(Status.waiting.name());
                    cloudAccountMapper.updateByPrimaryKeySelective(cloudAccountPO);
                }
            }
        }
    }

    @Override
    public void initCloudAccountCollectStatus() {
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().collectorStatus(Status.running.name()).build();
        List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);
        for (CloudAccountPO cloudAccountPO : cloudAccountPOS) {
            // 8h has not been scanned, the status is waiting
            if (cloudAccountPO.getLastScanTime() == null
                    || System.currentTimeMillis() - cloudAccountPO.getLastScanTime().getTime() > 8 * 60 * 60 * 1000) {
                cloudAccountPO.setCollectorStatus(Status.waiting.name());
                cloudAccountMapper.updateByPrimaryKeySelective(cloudAccountPO);
            }
        }
    }

    @Override
    public List<TaskResp> listCollectorTask(String persistentToken, String registryValue, String platform) throws Exception {
        AgentRegistryPO agentRegistryPO = checkPersistentToken(platform, registryValue, persistentToken);
        if (agentRegistryPO.getSecretKey() == null) {
            throw new RuntimeException(platform + ":" + registryValue + "SecretKey not exist");
        }

        return collectorTaskRepository.lockTask(agentRegistryPO.getRegistryValue(), platform);
    }
}

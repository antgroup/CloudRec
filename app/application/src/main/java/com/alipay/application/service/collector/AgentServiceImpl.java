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

import com.alipay.application.service.collector.domain.Agent;
import com.alipay.application.service.collector.domain.repo.AgentRepository;
import com.alipay.application.service.common.Platform;
import com.alipay.application.service.rule.job.ScanService;
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
import com.alipay.dao.dto.AgentRegistryDTO;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;
    @Resource
    private ScanService scanService;

    @Resource
    private CollectorLogMapper collectorLogMapper;

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

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
            agentRepository.del(agent.getId());
            return new ApiResponse<>(registryResponse);
        }

        if (agent == null) {
            agent = Agent.newAgent(registry.getPlatform(), registry.getRegistryValue(), registry.getCron(), registry.getAgentName(), registry.getSecretKey(), onceToken);
            agentRepository.save(agent);
        } else {
            agent.refreshAgent(registry.getOnceToken(), registry.getSecretKey());
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

    @Override
    public ApiResponse<ListVO<AgentRegistryVO>> queryAgentList(AgentRegistryDTO dto) {
        ListVO<AgentRegistryVO> listVO = new ListVO<>();
        int count = agentRegistryMapper.findCount(dto);
        if (count == 0) {
            return new ApiResponse<>(listVO);
        }

        dto.setOffset();
        List<AgentRegistryPO> list = agentRegistryMapper.findAggList(dto);
        List<AgentRegistryVO> collect = list.stream().map(AgentRegistryVO::build).toList();

        listVO.setData(collect);
        listVO.setTotal(count);

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
        String scriptTemplate = "curl -L -o %s.tar.gz %s/%s.tar.gz && tar -xzf %s.tar.gz && cd %s && nohup ./%s --serverUrl \"%s\" --accessToken \"%s\" > logs/task.log 2>&1 < /dev/null &";
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

        // ksyun  account
        String ksyunScript = parseScript(scriptTemplate, "deploy_ksyun", "cloudrec_collector_ksyun", bucketUrl, serverUrl, existPO.getOnceToken());
        result.add(createOnceToken(Platform.getPlatformName(PlatformType.KINGSOFT_CLOUD.getPlatform()), ksyunScript, userPO, existPO));

        // all account platforms
        String cloudRecScript = parseScript(scriptTemplate, "deploy_cloudrec", "cloudrec_collector", bucketUrl, serverUrl, existPO.getOnceToken());
        List<String> platformList = Platform.getPlatformNameList(PlatformType.ALI_CLOUD, PlatformType.TENCENT_CLOUD,
                PlatformType.BAIDU_CLOUD, PlatformType.HUAWEI_CLOUD, PlatformType.TENCENT_CLOUD, PlatformType.BAIDU_CLOUD, PlatformType.KINGSOFT_CLOUD);
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

    @Override
    public ApiResponse<List<AgentCloudAccountVO>> queryCloudAccountList(String persistentToken, String registryValue,
                                                                        String platform, List<String> sites) {
        AgentRegistryPO agentRegistryPO = checkPersistentToken(platform, registryValue, persistentToken);

        if (agentRegistryPO.getSecretKey() == null) {
            throw new RuntimeException(platform + ":" + registryValue + "SecretKey not exist");
        }

        AgentRegistryDTO agentRegistryDTO = new AgentRegistryDTO();
        agentRegistryDTO.setStatus(Status.valid.name());
        agentRegistryDTO.setPlatform(platform);
        List<AgentRegistryPO> agentList = agentRegistryMapper.findList(agentRegistryDTO);
        if (agentList.isEmpty()) {
            try {
                Thread.sleep(10 * 1000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            agentList = agentRegistryMapper.findList(agentRegistryDTO);
            if (agentList.isEmpty()) {
                throw new RuntimeException(platform + ":" + registryValue + "Abnormal heartbeat");
            }
        }

        // Get the number of accounts to be executed based on the currently surviving collector
        List<CloudAccountPO> list = cloudAccountMapper.findNotRunningAccount(platform, sites);
        if (list.isEmpty()) {
            throw new RuntimeException(platform + ":" + registryValue
                    + "The account accounts of the current platform are all in operation and account accounts cannot be allocated");
        }

        if (agentList.isEmpty()) {
            throw new RuntimeException(platform + ":" + registryValue + "There is currently no collector running");
        }

        if (agentList.size() != 1 && list.size() > agentList.size()) {
            list = list.stream().limit(Math.min(list.size() / agentList.size(), MAX_ACCOUNT_COUNT)).toList();
        } else {
            list = list.stream().limit(MAX_ACCOUNT_COUNT).toList();
        }

        List<AgentCloudAccountVO> collect = list.stream()
                .filter(po -> StringUtils.isNotBlank(po.getCredentialsJson()))
                .map(po -> {
                    try {
                        return AgentCloudAccountVO.build(po, agentRegistryPO.getSecretKey());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }).toList();

        updateAccountStatus(list, agentRegistryPO);

        return new ApiResponse<>(collect);
    }

    @Async
    void updateAccountStatus(List<CloudAccountPO> list, AgentRegistryPO agentRegistryPO) {
        // Change the status of this batch of account accounts to running
        list.forEach(cloudAccountPO -> {
            cloudAccountPO.setCollectorStatus(Status.running.name());
            cloudAccountPO.setLastScanTime(new Date());
            cloudAccountMapper.updateByPrimaryKeySelective(cloudAccountPO);

            // Bind the corresponding relationship between account account and collector
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
                    log.warn("Exceptions due to concurrent registrations");
                }
            }
        });
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


    @Override
    public void log(LogRequest logRequest) {
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
            collectorLogPO.setDescription(logRequest.getDescription());
            collectorLogMapper.insertSelective(collectorLogPO);
        } else {
            collectorLogPO.setTime(logRequest.getTime());
            collectorLogMapper.updateByPrimaryKeySelective(collectorLogPO);
        }
    }


    @Override
    public void runningFinishSignal(String cloudAccountId) {
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(cloudAccountId);
        if (cloudAccountPO == null) {
            return;
        }

        cloudAccountPO.setCollectorStatus(Status.waiting.name());
        cloudAccountPO.setLastScanTime(new Date());
        cloudAccountMapper.updateByPrimaryKeySelective(cloudAccountPO);

        // TODO 有性能问题，暂时不扫描
        // scanService.scanAll(cloudAccountPO.getPlatform(), cloudAccountPO.getCloudAccountId());
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
            }

            // If the patient is in a healthy state, a heartbeat of 1 minute will be changed to unhealthy.
            if (agentRegistryPO.getStatus().equals(Status.valid.name())) {
                if (System.currentTimeMillis() - agentRegistryPO.getRegistryTime().getTime() > 60 * 1000) {
                    agentRegistryPO.setStatus(Status.unusual.name());
                    agentRegistryMapper.updateByPrimaryKeySelective(agentRegistryPO);
                }
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
                if (cloudAccountPO != null) {
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
            if (cloudAccountPO.getLastScanTime() == null
                    || System.currentTimeMillis() - cloudAccountPO.getLastScanTime().getTime() > 60 * 1000) {
                cloudAccountPO.setCollectorStatus(Status.waiting.name());
                cloudAccountMapper.updateByPrimaryKeySelective(cloudAccountPO);
            }
        }
    }
}

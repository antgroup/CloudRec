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
package com.alipay.application.service.account;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.alipay.application.service.account.cloud.CredentialFactory;
import com.alipay.application.service.account.utils.AESEncryptionUtils;
import com.alipay.application.service.collector.domain.repo.CollectorTaskRepository;
import com.alipay.application.service.collector.enums.CollectorTaskType;
import com.alipay.application.service.common.utils.CacheUtil;
import com.alipay.application.service.common.utils.DbCacheUtil;
import com.alipay.application.service.resource.IQueryResource;
import com.alipay.application.share.request.account.AcceptAccountRequest;
import com.alipay.application.share.request.account.CreateCollectTaskRequest;
import com.alipay.application.share.request.account.QueryCloudAccountListRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.account.CloudAccountVO;
import com.alipay.common.constant.MarkConstants;
import com.alipay.common.enums.PlatformType;
import com.alipay.common.enums.Status;
import com.alipay.common.exception.BizException;
import com.alipay.common.utils.ListUtils;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.context.UserInfoDTO;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.mapper.CloudAccountMapper;
import com.alipay.dao.mapper.RuleScanResultMapper;
import com.alipay.dao.mapper.TenantMapper;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.DbCachePO;
import com.alipay.dao.po.TenantPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/*
 *@title CloudAccountServiceImpl
 *@description Cloud account service implementation class
 *@author jietian
 *@version 1.0
 *@create 2024/6/20 11:31
 */
@Slf4j
@Service
public class CloudAccountServiceImpl implements CloudAccountService {

    @Resource
    private CloudAccountMapper cloudAccountMapper;
    @Resource
    private RuleScanResultMapper ruleScanResultMapper;
    @Resource
    private IQueryResource iQueryResource;
    @Resource
    private TenantMapper tenantMapper;
    @Resource
    private CollectorTaskRepository collectorTaskRepository;
    @Resource
    private DbCacheUtil dbCacheUtil;

    private static final String cacheKey = "account::query_cloud_account_list";

    @Override
    public ApiResponse<ListVO<CloudAccountVO>> queryCloudAccountList(CloudAccountDTO cloudAccountDTO) {
        boolean needCache = false;
        UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
        String key = CacheUtil.buildKey(cacheKey, currentUser.getUserTenantId(), cloudAccountDTO.getStatus(), cloudAccountDTO.getPage(), cloudAccountDTO.getSize());
        if (ListUtils.isEmpty(cloudAccountDTO.getPlatformList())
                && StringUtils.isEmpty(cloudAccountDTO.getAccountStatus())
                && StringUtils.isEmpty(cloudAccountDTO.getCollectorStatus())
                && StringUtils.isEmpty(cloudAccountDTO.getCloudAccountId())) {
            needCache = true;
            DbCachePO dbCachePO = dbCacheUtil.get(key);
            if (dbCachePO != null) {
                ListVO<CloudAccountVO> listVO = JSON.parseObject(dbCachePO.getValue(), new TypeReference<>() {
                });
                return new ApiResponse<>(listVO);
            }
        }

        ListVO<CloudAccountVO> listVO = new ListVO<>();
        cloudAccountDTO.setTenantId(currentUser.getTenantId());
        int count = cloudAccountMapper.findCount(cloudAccountDTO);
        if (count == 0) {
            return new ApiResponse<>(listVO);
        }

        cloudAccountDTO.setOffset();
        List<CloudAccountPO> list = cloudAccountMapper.findList(cloudAccountDTO);

        List<CloudAccountVO> collect = list.parallelStream().map(CloudAccountVO::build).collect(Collectors.toList());
        listVO.setData(collect);
        listVO.setTotal(count);

        if (needCache) {
            dbCacheUtil.put(key, listVO);
        }
        return new ApiResponse<>(listVO);
    }

    @Override
    public ApiResponse<String> saveCloudAccount(CloudAccountDTO cloudAccountDTO) {
        // insert or update platform info
        if (cloudAccountDTO.getId() == null) {
            CloudAccountPO existPO = cloudAccountMapper.findByCloudAccountId(cloudAccountDTO.getCloudAccountId());
            if (existPO != null) {
                log.warn("Cloud account id already exists {}", cloudAccountDTO.getCloudAccountId());
                throw new RuntimeException("Cloud account id already exists");
            }
        }

        CloudAccountPO cloudAccountPO = new CloudAccountPO();
        cloudAccountPO.setCloudAccountId(cloudAccountDTO.getCloudAccountId());
        cloudAccountPO.setPlatform(cloudAccountDTO.getPlatform());
        cloudAccountPO.setTenantId(cloudAccountDTO.getTenantId());
        cloudAccountPO.setAlias(cloudAccountDTO.getAlias());
        cloudAccountPO.setSite(cloudAccountDTO.getSite());
        cloudAccountPO.setOwner(cloudAccountDTO.getOwner());
        if (StringUtils.isNoneEmpty(cloudAccountDTO.getCredentialsJson()) &&
                !Objects.equals(MarkConstants.emptyJSON, cloudAccountDTO.getCredentialsJson())
                && !cloudAccountDTO.getCredentialsJson().contains(MarkConstants.emptyJSON)) {
            boolean verification = CredentialFactory
                    .getCredential(cloudAccountDTO.getPlatform(), cloudAccountDTO.getCredentialsJson())
                    .verification();
            if (!verification) {
                log.warn("Cloud account credential verification failed {}", cloudAccountDTO.getCloudAccountId());
                throw new RuntimeException("Cloud account credential verification failed");
            } else {
                cloudAccountPO.setStatus(Status.valid.name());
                cloudAccountPO.setCredentialsJson(AESEncryptionUtils.encrypt(cloudAccountDTO.getCredentialsJson()));
            }
        }

        cloudAccountPO.setResourceTypeList(!ListUtils.isEmpty(cloudAccountDTO.getResourceTypeList()) ? String.join(",", cloudAccountDTO.getResourceTypeList()) : "");

        if (cloudAccountDTO.getId() == null) {
            if (UserInfoContext.getCurrentUser() != null) {
                cloudAccountPO.setUserId(UserInfoContext.getCurrentUser().getUserId());
            } else {
                cloudAccountPO.setUserId("SYSTEM");
            }
            cloudAccountPO.setCollectorStatus(Status.waiting.name());
            cloudAccountPO.setAccountStatus(Status.valid.name());
            cloudAccountMapper.insertSelective(cloudAccountPO);
        } else {
            cloudAccountPO.setId(cloudAccountDTO.getId());
            cloudAccountMapper.updateByPrimaryKeySelective(cloudAccountPO);
        }

        dbCacheUtil.clear(cacheKey);

        return ApiResponse.SUCCESS;
    }

    @Override
    public ApiResponse<String> removeCloudAccount(Long id) throws IOException {
        CloudAccountPO cloudAccountPO = cloudAccountMapper.selectByPrimaryKey(id);
        if (Objects.isNull(cloudAccountPO)) {
            throw new RuntimeException("account account is not exist");
        }
        // delete account account
        cloudAccountMapper.deleteByPrimaryKey(id);

        // delete account risk information
        ruleScanResultMapper.deleteByCloudAccountId(cloudAccountPO.getCloudAccountId());

        // delete account resource information
        iQueryResource.removeResource(cloudAccountPO.getCloudAccountId());

        dbCacheUtil.clear(cacheKey);

        log.warn("The account {} data has been deleted", cloudAccountPO.getCloudAccountId());
        return ApiResponse.SUCCESS;
    }

    @Override
    public ApiResponse<CloudAccountVO> queryCloudAccountDetail(Long id) {
        CloudAccountPO cloudAccountPO = cloudAccountMapper.selectByPrimaryKey(id);
        if (Objects.isNull(cloudAccountPO)) {
            throw new RuntimeException("account account is not exist");
        }
        CloudAccountVO cloudAccountVO = CloudAccountVO.build(cloudAccountPO);

        return new ApiResponse<>(cloudAccountVO);
    }

    @Transactional(rollbackFor = Exception.class)
    @Override
    public void updateCloudAccountStatus(String cloudAccountId, String accountStatus) {
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(cloudAccountId);
        if (Objects.isNull(cloudAccountPO)) {
            throw new RuntimeException("account account is not exist");
        }
        cloudAccountPO.setAccountStatus(accountStatus);
        cloudAccountPO.setCollectorStatus(Status.waiting.name());
        cloudAccountPO.setStatus(Status.valid.name());
        cloudAccountMapper.updateByPrimaryKeySelective(cloudAccountPO);

        dbCacheUtil.clear(cacheKey);
    }

    @Override
    public void acceptCloudAccount(AcceptAccountRequest request) {
        log.info("accept account: {}", request.getAccount());
        // check whether the tenant exists
        TenantPO tenantPO = tenantMapper.findByTenantName(request.getCiso());
        if (Objects.isNull(tenantPO)) {
            tenantPO = new TenantPO();
            tenantPO.setStatus(Status.valid.name());
            tenantPO.setTenantName(request.getCiso());
            tenantPO.setTenantDesc(request.getCiso());

            log.info("create ciso tenant: {}", request.getCiso());
            tenantMapper.insertSelective(tenantPO);
        }

        Map<String, String> credentialMap = new HashMap<>();
        credentialMap.put("ak", request.getAk());
        credentialMap.put("sk", request.getSk());

        // save account account
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().cloudAccountId(request.getYunid())
                .platform(PlatformType.ALI_CLOUD.getPlatform()).userId(request.getOwner()).credentialsJson(JSON.toJSONString(credentialMap))
                .alias(request.getAccount()).build();
        cloudAccountDTO.setTenantId(tenantPO.getId());
        cloudAccountDTO.setOwner(request.getOwner());

        CloudAccountPO cloudAccountPO = cloudAccountMapper.findOne(request.getYunid(), PlatformType.ALI_CLOUD.getPlatform());
        if (Objects.nonNull(cloudAccountPO)) {
            cloudAccountDTO.setId(cloudAccountPO.getId());
        }

        UserInfoDTO userInfoDTO = new UserInfoDTO();
        userInfoDTO.setUserId(request.getOwner());
        this.saveCloudAccount(cloudAccountDTO);
    }

    @Override
    public ApiResponse<Map<String, Object>> queryCloudAccountBaseInfoList(QueryCloudAccountListRequest request) {
        Map<String, Object> params = new HashMap<>();

        if (StringUtils.isEmpty(request.getCloudAccountSearch())
                || StringUtils.isEmpty(StringUtils.trim(request.getCloudAccountSearch()))) {
            List<String> cloudAccountBaseInfoList = new ArrayList<>();
            CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder()
                    .platformList(request.getPlatformList())
                    .tenantId(UserInfoContext.getCurrentUser().getTenantId())
                    .build();
            cloudAccountDTO.setPage(1);
            cloudAccountDTO.setSize(10);
            cloudAccountDTO.setOffset();
            List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);
            for (CloudAccountPO cloudAccountPO : cloudAccountPOS) {
                cloudAccountBaseInfoList.add(cloudAccountPO.getAlias());
            }

            params.put("accountAliasList", cloudAccountBaseInfoList);
        } else {
            List<String> cloudAccountBaseInfoList = new ArrayList<>();
            CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder()
                    .platformList(request.getPlatformList())
                    .cloudAccountSearch(request.getCloudAccountSearch())
                    .tenantId(UserInfoContext.getCurrentUser().getTenantId())
                    .build();
            List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);
            for (CloudAccountPO cloudAccountPO : cloudAccountPOS) {
                if (StringUtils.contains(cloudAccountPO.getAlias(), request.getCloudAccountSearch())) {
                    cloudAccountBaseInfoList.add(cloudAccountPO.getAlias());
                } else {
                    cloudAccountBaseInfoList.add(cloudAccountPO.getCloudAccountId());
                }
            }

            params.put("accountAliasList", cloudAccountBaseInfoList);
        }
        return new ApiResponse<>(params);
    }

    @Override
    public ApiResponse<List<Map<String, Object>>> queryCloudAccountBaseInfoListV2(QueryCloudAccountListRequest request) {
        List<Map<String, Object>> params = new ArrayList<>();
        if (StringUtils.isEmpty(request.getCloudAccountSearch()) || StringUtils.isEmpty(StringUtils.trim(request.getCloudAccountSearch()))) {

            CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder()
                    .platformList(request.getPlatformList())
                    .tenantId(UserInfoContext.getCurrentUser().getTenantId())
                    .build();
            cloudAccountDTO.setPage(1);
            cloudAccountDTO.setSize(10);
            cloudAccountDTO.setOffset();
            List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);
            for (CloudAccountPO cloudAccountPO : cloudAccountPOS) {
                Map<String, Object> map = new HashMap<>();
                map.put("cloudAccountId", cloudAccountPO.getCloudAccountId());
                map.put("alias", cloudAccountPO.getAlias());
                params.add(map);
            }
        } else {
            CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder()
                    .platformList(request.getPlatformList())
                    .cloudAccountSearch(request.getCloudAccountSearch())
                    .tenantId(UserInfoContext.getCurrentUser().getTenantId())
                    .build();
            List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);
            for (CloudAccountPO cloudAccountPO : cloudAccountPOS) {
                Map<String, Object> map = new HashMap<>();
                map.put("cloudAccountId", cloudAccountPO.getCloudAccountId());
                map.put("alias", cloudAccountPO.getAlias());
                params.add(map);
            }
        }
        return new ApiResponse<>(params);
    }

    @Override
    public void createCollectTask(CreateCollectTaskRequest request) {
        log.info("create collect task: {}", request.getCloudAccountId());
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(request.getCloudAccountId());
        if (Objects.isNull(cloudAccountPO)) {
            throw new BizException("account is not exist");
        }

        collectorTaskRepository.initTask(request.getCloudAccountId(), CollectorTaskType.collect.name());
    }
}

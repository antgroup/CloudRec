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
package com.alipay.application.service.resource;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.alipay.application.service.common.CloudAccount;
import com.alipay.application.service.common.utils.CacheUtil;
import com.alipay.application.service.common.utils.DbCacheUtil;
import com.alipay.application.service.resource.enums.AggregationType;
import com.alipay.application.service.resource.task.ResourceMergerTask;
import com.alipay.application.service.risk.RiskStatusManager;
import com.alipay.application.share.request.base.IdListRequest;
import com.alipay.application.share.request.resource.QueryResourceExampleDataRequest;
import com.alipay.application.share.request.resource.QueryResourceListRequest;
import com.alipay.application.share.request.rule.LinkDataParam;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.resource.ResourceGroupTypeVO;
import com.alipay.application.share.vo.resource.ResourceInstanceVO;
import com.alipay.application.share.vo.resource.ResourceRiskCountVO;
import com.alipay.common.constant.TenantConstants;
import com.alipay.common.enums.ResourceGroupType;
import com.alipay.common.exception.BizException;
import com.alipay.common.utils.ListUtils;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.context.UserInfoDTO;
import com.alipay.dao.dto.*;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.*;

/*
 *@title EsTest
 *@description
 *@author jietian
 *@version 1.0
 *@create 2023/12/19 11:37
 */
@Slf4j
@Service
public class QueryResourceImpl implements IQueryResource {

    @Resource
    private ResourceMapper resourceMapper;

    @Resource
    private CloudAccount cloudAccount;

    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private CloudResourceRiskCountStatisticsMapper cloudResourceRiskCountStatisticsMapper;

    @Resource
    private DbCacheUtil dbCacheUtil;

    @Resource
    private CloudAccountMapper cloudAccountMapper;

    private static final String cacheKey = "risk::query_resource_list";

    @Override
    public List<CloudResourceInstancePO> queryByCond(String platform, String resourceType, String cloudAccountId) {
        final int size = 1000;
        List<CloudResourceInstancePO> result = new ArrayList<>();
        Long scrollId = 0L;
        while (true) {
            IQueryResourceDTO request = IQueryResourceDTO.builder().platform(platform)
                    .resourceType(resourceType)
                    .cloudAccountId(cloudAccountId)
                    .scrollId(scrollId)
                    .size(size)
                    .build();
            List<CloudResourceInstancePO> cloudResourceInstancePOS = cloudResourceInstanceMapper.findByCondWithScrollId(request);
            if (CollectionUtils.isEmpty(cloudResourceInstancePOS)) {
                return result;
            } else {
                result.addAll(cloudResourceInstancePOS);
                if (cloudResourceInstancePOS.size() < size) {
                    return result;
                }
                scrollId = cloudResourceInstancePOS.get(cloudResourceInstancePOS.size() - 1).getId();
            }
        }
    }

    @Override
    public List<CloudResourceInstancePO> queryByCond(@NotNull String platform, @NotNull String resourceType, @NotNull String cloudAccountId, @NotNull Long scrollId, @NotNull Integer size) {
        Assert.notNull(platform, "platform is null");
        Assert.notNull(resourceType, "resourceType is null");
        Assert.notNull(cloudAccountId, "cloudAccountId is null");
        Assert.notNull(scrollId, "offset is null");
        Assert.notNull(size, "size is null");
        IQueryResourceDTO request = IQueryResourceDTO.builder()
                .platform(platform)
                .resourceType(resourceType)
                .cloudAccountId(cloudAccountId)
                .scrollId(scrollId)
                .size(size)
                .build();
        return cloudResourceInstanceMapper.findByCondWithScrollId(request);
    }

    @Override
    public List<CloudResourceInstancePO> queryByCondX(String platform, String resourceType, String cloudAccountId, String resourceId, Integer limit) {
        if (limit == null || limit == 0) {
            return List.of();
        }
        IQueryResourceDTO request = IQueryResourceDTO.builder()
                .platform(platform)
                .resourceType(resourceType)
                .cloudAccountId(cloudAccountId)
                .resourceIdEq(resourceId)
                .offset(0)
                .size(limit)
                .build();
        return cloudResourceInstanceMapper.findByCond(request);
    }

    @Override
    public CloudResourceInstancePO queryResource(IQueryResourceDTO request) {
        List<CloudResourceInstancePO> cloudResourceInstancePOS = cloudResourceInstanceMapper.findByCondWithScrollId(request);
        if (CollectionUtils.isEmpty(cloudResourceInstancePOS)) {
            return null;
        }
        return cloudResourceInstancePOS.get(0);
    }

    @Override
    public CloudResourceInstancePO query(String platform, String resourceType, String cloudAccountId,
                                         String resourceId) {
        IQueryResourceDTO request = IQueryResourceDTO.builder().resourceType(resourceType).platform(platform)
                .cloudAccountId(cloudAccountId).resourceIdEq(resourceId).size(1).build();
        List<CloudResourceInstancePO> list = cloudResourceInstanceMapper.findByCondWithScrollId(request);
        if (CollectionUtils.isEmpty(list)) {
            return null;
        }
        return list.get(0);
    }

    /**
     * @param cloudAccountId 云账号id
     */
    @Override
    public long queryResourceCount(String cloudAccountId) {
        return cloudResourceInstanceMapper.findCountByCloudAccountId(cloudAccountId);
    }

    @Override
    public ApiResponse<List<ResourcePO>> queryTypeList(String platform) {
        List<ResourcePO> list = resourceMapper.findByPlatform(platform);
        return new ApiResponse<>(list);
    }

    @Override
    public ApiResponse<ListVO<ResourceInstanceVO>> queryResourceList(QueryResourceListRequest request) {
        boolean needCache = false;
        String key = CacheUtil.buildKey(cacheKey, request.getPlatformList(),
                request.getResourceTypeList(),
                UserInfoContext.getCurrentUser().getUserTenantId(),
                request.getPage(),
                request.getSize());

        if (StringUtils.isEmpty(request.getCloudAccountId())
                && StringUtils.isEmpty(request.getSearchParam())
                && StringUtils.isEmpty(request.getAddress())
                && StringUtils.isEmpty(request.getCustomFieldValue())) {
            needCache = true;
            DbCachePO dbCachePO = dbCacheUtil.get(key);
            if (dbCachePO != null) {
                ListVO<ResourceInstanceVO> listVO = JSON.parseObject(dbCachePO.getValue(), new TypeReference<>() {
                });
                return new ApiResponse<>(listVO);
            }
        }
        IQueryResourceDTO dto = IQueryResourceDTO.builder().resourceTypeList(ListUtils.setList(request.getResourceTypeList()))
                .platform(request.getPlatform())
                .platformList(request.getPlatformList())
                .alias(request.getCloudAccountId())
                .cloudAccountIdList(cloudAccount.queryCloudAccountIdList(request.getCloudAccountId()))
                .address(request.getAddress())
                .resourceId(request.getResourceId())
                .resourceName(request.getResourceName())
                .searchParam(request.getSearchParam())
                .sortParam(request.getSortParam())
                .sortType(request.getSortType())
                .instance(request.getInstance())
                .tenantId(UserInfoContext.getCurrentUser().getTenantId())
                .customFieldValue(request.getCustomFieldValue())
                .page(request.getPage())
                .size(request.getSize())
                .offset((request.getPage() - 1) * request.getSize()).build();


        ListVO<ResourceInstanceVO> listVO = new ListVO<>();
        long count = cloudResourceInstanceMapper.findCountByCond(dto);
        if (count == 0) {
            return new ApiResponse<>(listVO);
        }

        List<CloudResourceInstancePO> cloudResourceInstancePOS = cloudResourceInstanceMapper.findByCond(dto);
        List<ResourceInstanceVO> collect = cloudResourceInstancePOS.stream().map(ResourceInstanceVO::build).toList();
        listVO.setData(collect);
        listVO.setTotal((int) count);

        if (needCache) {
            dbCacheUtil.put(key, listVO);
        }

        return new ApiResponse<>(listVO);
    }

    @Override
    public ResourceInstanceVO queryResourceDetail(Long id) {
        CloudResourceInstancePO cloudResourceInstancePO = cloudResourceInstanceMapper.selectByPrimaryKey(id);
        if (cloudResourceInstancePO == null) {
            throw new RuntimeException("Resource does not exist");
        }

        UserInfoDTO currentUser = UserInfoContext.getCurrentUser();
        if (currentUser.getTenantId() != null) {
            if (!TenantConstants.GLOBAL_TENANT.equals(currentUser.getTenantName())) {
                if (!currentUser.getTenantId().equals(cloudResourceInstancePO.getTenantId())) {
                    throw new BizException("No cross-tenant access");
                }
            }
        }
        ResourceInstanceVO resourceInstanceVO = ResourceInstanceVO.build(cloudResourceInstancePO);
        resourceInstanceVO.setInstance(JSON.parseObject(cloudResourceInstancePO.getInstance(), Map.class));

        return resourceInstanceVO;
    }

    @Override
    public ApiResponse<List<ResourceGroupTypeVO>> queryGroupTypeList(List<String> platformList) {
        List<ResourceGroupTypeVO> voList = new ArrayList<>();
        ResourceGroupType[] values = ResourceGroupType.values();
        for (ResourceGroupType value : values) {
            List<ResourcePO> list = resourceMapper.findByGroupType(platformList, value.getCode());
            if (list.isEmpty()) {
                continue;
            }
            ResourceGroupTypeVO parent = new ResourceGroupTypeVO();
            parent.setValue(value.getCode());
            parent.setLabel(value.getDesc());

            List<ResourceGroupTypeVO> children = new ArrayList<>();
            for (ResourcePO resourcePO : list) {
                ResourceGroupTypeVO child = new ResourceGroupTypeVO();
                child.setLabel(resourcePO.getResourceName());
                child.setValue(resourcePO.getResourceType());
                children.add(child);
            }

            parent.setChildren(children);
            voList.add(parent);
        }

        return new ApiResponse<>(voList);
    }

    @Override
    public ApiResponse<Object> queryResourceExampleData(QueryResourceExampleDataRequest request) {
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().build();
        cloudAccountDTO.setPlatform(request.getPlatform());
        CloudResourceInstancePO cloudResourceInstancePO = null;
        if (Strings.isNotBlank(request.getResourceId())) {
            cloudResourceInstancePO = cloudResourceInstanceMapper.findByResourceId(request.getPlatform(), request.getResourceType().get(1), request.getResourceId());

        } else {
            cloudResourceInstancePO = cloudResourceInstanceMapper.findExampleLimit1(request.getPlatform(), request.getResourceType().get(1));
        }
        if (cloudResourceInstancePO == null) {
            throw new BizException("No sample data yet");
        }

        if (request.getLinkedDataList() != null && !request.getLinkedDataList().isEmpty()) {
            List<CloudResourceInstancePO> cloudResourceInstanceList = queryByCondX(request.getPlatform(), request.getResourceType().get(1), cloudResourceInstancePO.getCloudAccountId(), request.getResourceId(), 1);
            cloudResourceInstanceList = ResourceMergerTask.mergeJsonWithTimeOut(request.getLinkedDataList(), cloudResourceInstanceList, cloudResourceInstancePO.getCloudAccountId());

            Map<Long, Integer> scoreMap = new HashMap<>();
            for (CloudResourceInstancePO item : cloudResourceInstanceList) {
                scoreMap.put(item.getId(), 0);
                for (LinkDataParam linkedData : request.getLinkedDataList()) {
                    if (item.getInstance().contains(linkedData.getNewKeyName())) {
                        scoreMap.put(item.getId(), scoreMap.get(item.getId()) + 1);
                    }
                }
            }

            List<CloudResourceInstancePO> collect = cloudResourceInstanceList
                    .stream()
                    .sorted(Comparator.comparing(e -> scoreMap.get(e.getId())))
                    .toList();
            return new ApiResponse<>(JSON.parse(collect.get(collect.size() - 1).getInstance()));
        }

        return new ApiResponse<>(JSON.parse(cloudResourceInstancePO.getInstance()));

    }


    @Override
    public ApiResponse<ListVO<ResourceAggByInstanceTypeDTO>> queryAggregateAssets(ResourceDTO resourceDTO) {
        boolean needCache = false;
        String key = CacheUtil.buildKey("queryAggregateAssets", resourceDTO.getAggregationType(),
                resourceDTO.getPlatformList(),
                resourceDTO.getResourceTypeList(),
                UserInfoContext.getCurrentUser().getTenantId(),
                resourceDTO.getPage(),
                resourceDTO.getSize());

        if (StringUtils.isEmpty(resourceDTO.getCloudAccountId())
                && StringUtils.isEmpty(resourceDTO.getSearchParam())
                && StringUtils.isEmpty(resourceDTO.getAddress())) {
            needCache = true;
            DbCachePO dbCachePO = dbCacheUtil.get(key);
            if (dbCachePO != null) {
                ListVO<ResourceAggByInstanceTypeDTO> listVO = JSON.parseObject(dbCachePO.getValue(), new TypeReference<>() {
                });
                return new ApiResponse<>(listVO);
            }
        }

        resourceDTO.setTenantId(UserInfoContext.getCurrentUser().getTenantId());
        resourceDTO.setCloudAccountIdList(cloudAccount.queryCloudAccountIdList(resourceDTO.getCloudAccountId()));

        ListVO<ResourceAggByInstanceTypeDTO> listVO = new ListVO<>();

        // Determine which aggregation method to use based on aggregationType
        int count;
        List<ResourceAggByInstanceTypeDTO> list;

        if (AggregationType.CLOUD_ACCOUNT.getCode().equals(resourceDTO.getAggregationType())) {
            // Aggregate by cloud account
            count = cloudResourceInstanceMapper.findAggregateAssetsByCloudAccountCount(resourceDTO);
            if (count == 0) {
                return new ApiResponse<>(listVO);
            }
            resourceDTO.setOffset();
            list = cloudResourceInstanceMapper.findAggregateAssetsByCloudAccountList(resourceDTO);
        } else {
            // Default: aggregate by resource type
            count = cloudResourceInstanceMapper.findAggregateAssetsCount(resourceDTO);
            if (count == 0) {
                return new ApiResponse<>(listVO);
            }
            resourceDTO.setOffset();
            list = cloudResourceInstanceMapper.findAggregateAssetsList(resourceDTO);
        }

        list = list.stream().parallel().map(dto -> {
            // query new resource condition
            ResourceDTO queryDTO = new ResourceDTO();
            BeanUtils.copyProperties(resourceDTO, queryDTO);

            if (AggregationType.CLOUD_ACCOUNT.getCode().equals(resourceDTO.getAggregationType())) {
                // query cloud account alias
                CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(dto.getCloudAccountId());
                if (cloudAccountPO != null) {
                    dto.setAlias(cloudAccountPO.getAlias());
                }

                // query risk by cloud account
                RuleScanResultDTO resultDTO = RuleScanResultDTO.builder()
                        .cloudAccountIdList(Collections.singletonList(dto.getCloudAccountId()))
                        .resourceTypeList(resourceDTO.getResourceTypeList())
                        .resourceIdOrName(resourceDTO.getSearchParam())
                        .build();
                RiskCountDTO riskCountDTO = ruleScanResultMapper.findRiskCount(resultDTO);
                dto.setHighLevelRiskCount(riskCountDTO.getHighLevelRiskCount());
                dto.setMediumLevelRiskCount(riskCountDTO.getMediumLevelRiskCount());
                dto.setLowLevelRiskCount(riskCountDTO.getLowLevelRiskCount());

                // query new resource
                queryDTO.setCloudAccountIdList(Collections.singletonList(dto.getCloudAccountId()));
            } else {
                // For resource type aggregation, query resource type name
                ResourcePO resourcePO = resourceMapper.findOne(dto.getPlatform(), dto.getResourceType());
                if (resourcePO == null) {
                    cloudResourceInstanceMapper.deleteByResourceType(dto.getPlatform(), dto.getResourceType());
                    return null;
                }

                dto.setResourceTypeName(resourcePO.getResourceName());
                List<String> typeFullNameList = new ArrayList<>();
                typeFullNameList.add(resourcePO.getResourceGroupType());
                typeFullNameList.add(resourcePO.getResourceType());
                dto.setTypeFullNameList(List.of(typeFullNameList));

                // query risk by resource type
                CloudResourceRiskCountStatisticsPO cloudResourceRiskCountStatisticsPO = cloudResourceRiskCountStatisticsMapper.findOne(resourcePO.getPlatform(), resourcePO.getResourceType(), UserInfoContext.getCurrentUser().getTenantId());
                if (cloudResourceRiskCountStatisticsPO != null) {
                    dto.setHighLevelRiskCount(cloudResourceRiskCountStatisticsPO.getHighLevelRiskCount());
                    dto.setMediumLevelRiskCount(cloudResourceRiskCountStatisticsPO.getMediumLevelRiskCount());
                    dto.setLowLevelRiskCount(cloudResourceRiskCountStatisticsPO.getLowLevelRiskCount());
                } else {
                    dto.setHighLevelRiskCount(0);
                    dto.setMediumLevelRiskCount(0);
                    dto.setLowLevelRiskCount(0);
                }

                // query new resource
                queryDTO.setResourceTypeList(List.of(dto.getResourceType()));
            }

            CloudResourceInstancePO cloudResourceInstancePO = cloudResourceInstanceMapper.findLatestOne(queryDTO);
            if (cloudResourceInstancePO != null) {
                ResourceAggByInstanceTypeDTO.LatestResourceInfo latestResourceInfo = new ResourceAggByInstanceTypeDTO.LatestResourceInfo();
                latestResourceInfo.setResourceId(cloudResourceInstancePO.getResourceId());
                latestResourceInfo.setResourceName(cloudResourceInstancePO.getResourceName());
                latestResourceInfo.setGmtModified(cloudResourceInstancePO.getGmtModified());
                latestResourceInfo.setAddress(cloudResourceInstancePO.getAddress());
                dto.setLatestResourceInfo(latestResourceInfo);
            }

            return dto;
        }).filter(Objects::nonNull).toList();

        listVO.setData(list);
        listVO.setTotal(count);

        if (needCache) {
            dbCacheUtil.put(key, listVO);
        }

        return new ApiResponse<>(listVO);
    }

    @Override
    public ApiResponse<List<ResourceRiskCountVO>> queryResourceRiskQuantity(IdListRequest idListRequest) {
        List<CloudResourceInstancePO> cloudResourceInstancePOS = cloudResourceInstanceMapper.findByIdList(idListRequest.getIdList());

        List<ResourceRiskCountVO> result = new ArrayList<>();
        for (CloudResourceInstancePO po : cloudResourceInstancePOS) {
            ResourceRiskCountVO resourceRiskCountVO = new ResourceRiskCountVO();
            RuleScanResultDTO ruleScanResultDTO = RuleScanResultDTO.builder()
                    .platform(po.getPlatform())
                    .status(RiskStatusManager.RiskStatus.UNREPAIRED.name())
                    .resourceType(po.getResourceType())
                    .resourceId(po.getResourceId())
                    .build();

            RiskCountDTO riskCountDTO = ruleScanResultMapper.findRiskCount(ruleScanResultDTO);
            resourceRiskCountVO.setHighLevelRiskCount(riskCountDTO.getHighLevelRiskCount());
            resourceRiskCountVO.setMediumLevelRiskCount(riskCountDTO.getMediumLevelRiskCount());
            resourceRiskCountVO.setLowLevelRiskCount(riskCountDTO.getLowLevelRiskCount());
            resourceRiskCountVO.setTotalRiskCount(riskCountDTO.getTotalRiskCount());
            resourceRiskCountVO.setId(po.getId());
            result.add(resourceRiskCountVO);
        }

        return new ApiResponse<>(result);
    }
}

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

import com.alipay.dao.dto.IQueryResourceDTO;
import com.alipay.dao.dto.ResourceAggByInstanceTypeDTO;
import com.alipay.dao.dto.ResourceDTO;
import com.alipay.dao.po.CloudResourceInstancePO;
import org.apache.ibatis.annotations.Param;

import java.util.Date;
import java.util.List;

public interface CloudResourceInstanceMapper {
    int deleteByPrimaryKey(Long id);

    int insertSelective(CloudResourceInstancePO record);

    CloudResourceInstancePO selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(CloudResourceInstancePO record);

    CloudResourceInstancePO findOne(@Param("platform") String platform,
                                    @Param("resourceType") String resourceType,
                                    @Param("cloudAccountId") String cloudAccountId,
                                    @Param("resourceId") String resourceId);

    CloudResourceInstancePO findByResourceId(@Param("platform") String platform,
                                             @Param("resourceType") String resourceType,
                                             @Param("resourceId") String resourceId);

    CloudResourceInstancePO findExampleLimit1(@Param("platform") String platform,
                                              @Param("resourceType") String resourceType);

    List<CloudResourceInstancePO> findByCondWithScrollId(IQueryResourceDTO request);

    List<CloudResourceInstancePO> findByCond(IQueryResourceDTO request);

    long findCountByCloudAccountId(String cloudAccountId);

    int deleteByCloudAccountId(String cloudAccountId);

    // 预删除
    int preDeleteByIdList(@Param("idList") List<Long> idList, @Param("deleteAt") Date deleteAt);

    // 正式删除
    int commitDeleteByCloudAccountId(@Param("cloudAccountId") String cloudAccountId, @Param("delNum") int delNum);

    int deleteByModified(@Param("cloudAccountId") String cloudAccountId, @Param("day") int day);

    long findCountByCond(IQueryResourceDTO dto);

    int findAggregateAssetsCount(ResourceDTO resourceDTO);

    List<ResourceAggByInstanceTypeDTO> findAggregateAssetsList(ResourceDTO resourceDTO);

    /**
     * Find aggregate assets count by cloud account
     * @param resourceDTO query parameters
     * @return count of aggregated assets by cloud account
     */
    int findAggregateAssetsByCloudAccountCount(ResourceDTO resourceDTO);

    /**
     * Find aggregate assets list by cloud account
     * @param resourceDTO query parameters
     * @return list of aggregated assets by cloud account
     */
    List<ResourceAggByInstanceTypeDTO> findAggregateAssetsByCloudAccountList(ResourceDTO resourceDTO);

    /**
     * 根据条件查询最新的资源实例
     *
     * @param resourceDTO dto
     * @return CloudResourceInstancePO
     */
    CloudResourceInstancePO findLatestOne(ResourceDTO resourceDTO);


    /**
     * 逻辑删除
     *
     * @param idList 资产id list
     * @return 影响记录数
     */
    int deletedByIdList(@Param("idList") List<Long> idList);


    /**
     * 根据id列表查询
     *
     * @param idList id list
     * @return 资源list
     */
    List<CloudResourceInstancePO> findByIdList(@Param("idList") List<Long> idList);

    /**
     * Query the account id list with account assets
     *
     * @param platform
     * @param resourceType
     * @return list of account id
     */
    List<String> findAccountList(@Param("platform") String platform, @Param("resourceType") String resourceType);


    List<String> getResourceIdList();

    int deleteDiscardedData(@Param("cloudAccountId") String cloudAccountId, @Param("resourceType") String resourceType);

    int deleteByResourceType(@Param("platform") String platform, @Param("resourceType") String resourceType);

    List<Long> findPreDeletedDataIdList(@Param("cloudAccountId") String cloudAccountId, @Param("delNum") int delNum);
}
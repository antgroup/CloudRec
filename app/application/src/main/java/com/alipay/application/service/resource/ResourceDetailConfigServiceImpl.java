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
import com.alipay.application.share.request.resource.QueryDetailConfigListRequest;
import com.alipay.application.share.request.resource.SaveDetailConfigRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.resource.ResourceDetailConfigVO;
import com.alipay.common.enums.ResourceDetailConfigType;
import com.alipay.common.enums.Status;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.dto.IQueryResourceDTO;
import com.alipay.dao.mapper.ResourceDetailConfigMapper;
import com.alipay.dao.po.CloudResourceInstancePO;
import com.alipay.dao.po.ResourceDetailConfigPO;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import jakarta.annotation.Resource;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/*
 *@title ResourceDetailConfigServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/8/12 09:31
 */
@Slf4j
@Service
public class ResourceDetailConfigServiceImpl implements ResourceDetailConfigService {

    @Resource
    private ResourceDetailConfigMapper resourceDetailConfigMapper;

    @Resource
    private IQueryResource iQueryResource;

    @Transactional(rollbackFor = Exception.class)
    @Override
    public ApiResponse<String> saveDetailConfig(Map<String, List<SaveDetailConfigRequest>> request) {
        String username = UserInfoContext.getCurrentUser().getUsername();
        List<SaveDetailConfigRequest> saveDetailConfigRequests = request.get(ResourceDetailConfigType.BASE_INFO.name());
        saveData(saveDetailConfigRequests, ResourceDetailConfigType.BASE_INFO.name(), username);

        saveDetailConfigRequests = request.get(ResourceDetailConfigType.NETWORK.name());
        saveData(saveDetailConfigRequests, ResourceDetailConfigType.NETWORK.name(), username);

        return ApiResponse.SUCCESS;
    }

    private void saveData(List<SaveDetailConfigRequest> saveDetailConfigRequests, String type, String username) {
        if (saveDetailConfigRequests != null && !saveDetailConfigRequests.isEmpty()) {
            resourceDetailConfigMapper.deleteOne(saveDetailConfigRequests.get(0).getResourceType(),
                    saveDetailConfigRequests.get(0).getPlatform(), type);
            for (SaveDetailConfigRequest detail : saveDetailConfigRequests) {
                ResourceDetailConfigPO resourceDetailConfigPO = new ResourceDetailConfigPO();
                resourceDetailConfigPO.setPlatform(detail.getPlatform());
                resourceDetailConfigPO.setResourceType(detail.getResourceType());
                resourceDetailConfigPO.setName(detail.getName());
                resourceDetailConfigPO.setPath(detail.getPath());
                resourceDetailConfigPO.setType(type);
                resourceDetailConfigPO.setUser(username);
                resourceDetailConfigPO.setModified(1);
                if (detail.getStatus() == null) {
                    resourceDetailConfigPO.setStatus(Status.valid.name());
                } else {
                    resourceDetailConfigPO.setStatus(detail.getStatus());
                }

                resourceDetailConfigMapper.insertSelective(resourceDetailConfigPO);
            }
        }
    }

    @SneakyThrows
    @Override
    public ApiResponse<Map<String, List<ResourceDetailConfigVO>>> queryDetailConfigList(
            QueryDetailConfigListRequest request, String status) {
        List<ResourceDetailConfigPO> list = resourceDetailConfigMapper.findList(request.getPlatform(),
                request.getResourceType(), null, status);
        if (list == null) {
            return new ApiResponse<>("No configuration yet");
        }

        IQueryResourceDTO iQueryResourceDTO = IQueryResourceDTO.builder()
                .resourceIdEq(request.getResourceIdEq()).platform(request.getPlatform())
                .resourceType(request.getResourceType()).size(1).build();

        // Query asset data
        CloudResourceInstancePO resourceInstance = iQueryResource.queryResource(iQueryResourceDTO);

        // Parse asset data
        Object document = Configuration.defaultConfiguration().jsonProvider().parse(resourceInstance.getInstance());

        // Basic information
        List<ResourceDetailConfigVO> baseinfoList = new ArrayList<>();
        List<ResourceDetailConfigPO> baseInfoConfigList = resourceDetailConfigMapper.findList(request.getPlatform(),
                request.getResourceType(), ResourceDetailConfigType.BASE_INFO.name(), status);
        getPath(document, baseinfoList, baseInfoConfigList);
        Map<String, List<ResourceDetailConfigVO>> result = new HashMap<>();
        result.put(ResourceDetailConfigType.BASE_INFO.name(), baseinfoList);

        // Network information
        List<ResourceDetailConfigVO> networkList = new ArrayList<>();
        List<ResourceDetailConfigPO> networkConfigList = resourceDetailConfigMapper.findList(request.getPlatform(),
                request.getResourceType(), ResourceDetailConfigType.NETWORK.name(), status);
        getPath(document, networkList, networkConfigList);
        result.put(ResourceDetailConfigType.NETWORK.name(), networkList);
        return new ApiResponse<>(result);
    }

    private void getPath(Object document, List<ResourceDetailConfigVO> networkList,
                         List<ResourceDetailConfigPO> networkConfigList) {
        for (ResourceDetailConfigPO po : networkConfigList) {
            ResourceDetailConfigVO vo = ResourceDetailConfigVO.build(po);
            try {
                Object read = JsonPath.read(document, po.getPath());
                String value = JSON.toJSONString(read);
                vo.setValue(value);
            } catch (Exception e) {
                log.warn("jsonpath error:{}", po.getPath(), e);
                vo.setValue(e.getMessage());
            }
            networkList.add(vo);
        }
    }
}

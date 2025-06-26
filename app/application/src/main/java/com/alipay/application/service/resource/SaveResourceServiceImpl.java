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
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alipay.application.share.request.resource.DataPushRequest;
import com.alipay.application.share.request.resource.ResourceInstance;
import com.alipay.application.share.vo.resource.ResourceDetailConfigVO;
import com.alipay.common.enums.Status;
import com.alipay.dao.mapper.CloudAccountMapper;
import com.alipay.dao.mapper.CloudResourceInstanceMapper;
import com.alipay.dao.mapper.ResourceDetailConfigMapper;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.CloudResourceInstancePO;
import com.alipay.dao.po.ResourceDetailConfigPO;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Slf4j
@Service
public class SaveResourceServiceImpl implements SaveResourceService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SaveResourceServiceImpl.class);

    @Resource
    private CloudAccountMapper cloudAccountMapper;

    @Resource
    private ResourceDetailConfigMapper resourceDetailConfigMapper;

    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;


    public void saveOrUpdateData(DataPushRequest.Data dataPushRequest) {
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(dataPushRequest.getCloudAccountId());
        if (cloudAccountPO == null) {
            LOGGER.error("account account not found, cloudAccountId:{}", dataPushRequest.getCloudAccountId());
            return;
        }

        try {
            for (ResourceInstance resourceInstance : dataPushRequest.getResourceInstancesAll()) {
                CloudResourceInstancePO cloudResourceInstancePO = cloudResourceInstanceMapper.findOne(dataPushRequest.getPlatform(), dataPushRequest.getResourceType(), dataPushRequest.getCloudAccountId(), resourceInstance.getResourceId());
                if (cloudResourceInstancePO == null) {
                    cloudResourceInstancePO = new CloudResourceInstancePO();
                    cloudResourceInstancePO.setAddress(resourceInstance.getAddress());
                    cloudResourceInstancePO.setCloudAccountId(dataPushRequest.getCloudAccountId());
                    cloudResourceInstancePO.setAlias(cloudAccountPO.getAlias());
                    cloudResourceInstancePO.setResourceType(dataPushRequest.getResourceType());
                    cloudResourceInstancePO.setPlatform(dataPushRequest.getPlatform());
                    cloudResourceInstancePO.setResourceId(resourceInstance.getResourceId());
                    cloudResourceInstancePO.setResourceName(resourceInstance.getResourceName());
                    cloudResourceInstancePO.setInstance(JSON.toJSONString(resourceInstance.getInstance(), SerializerFeature.WriteMapNullValue));
                    cloudResourceInstancePO.setVersion(dataPushRequest.getVersion());
                    cloudResourceInstancePO.setTenantId(cloudAccountPO.getTenantId());
                    cloudResourceInstancePO.setCustomFieldValue(parseCustomField(cloudResourceInstancePO));
                    cloudResourceInstanceMapper.insertSelective(cloudResourceInstancePO);
                } else {
                    cloudResourceInstancePO.setResourceName(resourceInstance.getResourceName());
                    cloudResourceInstancePO.setInstance(JSON.toJSONString(resourceInstance.getInstance(), SerializerFeature.WriteMapNullValue));
                    cloudResourceInstancePO.setAddress(resourceInstance.getAddress());
                    cloudResourceInstancePO.setVersion(dataPushRequest.getVersion());
                    cloudResourceInstancePO.setTenantId(cloudAccountPO.getTenantId());
                    cloudResourceInstancePO.setGmtModified(new Date());
                    cloudResourceInstancePO.setCustomFieldValue(parseCustomField(cloudResourceInstancePO));
                    // Clean up pre-delete tags
                    cloudResourceInstancePO.setDeletedAt(null);
                    cloudResourceInstancePO.setDelNum(0);
                    cloudResourceInstanceMapper.updateByPrimaryKeySelective(cloudResourceInstancePO);
                }
            }
        } catch (Exception e) {
            LOGGER.error("save resource instance error", e);
        }
    }


    @Override
    public void acceptResourceData(DataPushRequest dataReq) {
        String data = dataReq.getData();
        DataPushRequest.Data parseObject = JSON.parseObject(data, DataPushRequest.Data.class);

        try {
            this.saveOrUpdateData(parseObject);
        } catch (Exception e) {
            LOGGER.error("error", e);
        }
    }

    public String parseCustomField(CloudResourceInstancePO resourceInstance) {
        // Query all configurations
        List<ResourceDetailConfigPO> list = resourceDetailConfigMapper.findList(resourceInstance.getPlatform(),
                resourceInstance.getResourceType(), null, Status.valid.name());
        if (CollectionUtils.isEmpty(list)) {
            return null;
        }

        // Parse asset data
        Object document = Configuration.defaultConfiguration().jsonProvider().parse(resourceInstance.getInstance());
        List<String> fieldValueList = getPath(document, list);
        if (CollectionUtils.isEmpty(fieldValueList)) {
            return null;
        }

        return Strings.join(fieldValueList, ',');
    }

    private List<String> getPath(Object document, List<ResourceDetailConfigPO> list) {
        List<String> result = new ArrayList<>();
        for (ResourceDetailConfigPO po : list) {
            try {
                result.add(JSON.toJSONString(JsonPath.read(document, po.getPath())));
            } catch (Exception e) {
                log.error("jsonpath error:{}", po.getPath(), e);
            }
        }

        return result;
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
                LOGGER.info("jsonpath error:{}", po.getPath());
                vo.setValue(e.getMessage());
            }
            networkList.add(vo);
        }
    }
}

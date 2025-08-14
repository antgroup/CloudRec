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
package com.alipay.application.service.resource.task;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.application.service.common.utils.TaskExecutor;
import com.alipay.application.service.resource.IQueryResource;
import com.alipay.application.share.request.rule.LinkDataParam;
import com.alipay.common.enums.AssociativeMode;
import com.alipay.dao.po.CloudResourceInstancePO;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

@Setter
@Getter
@Slf4j
public class ResourceMergerTask implements Callable<List<CloudResourceInstancePO>> {

    /**
     * Maximum waiting time for task execution 5 min
     */
    public static int MAX_TIME_OUT_MILLISECONDS = 1000 * 60 * 5;

    /**
     * Associated data str
     */
    private List<LinkDataParam> linkedDataList;

    /**
     * Need to mount the original data of new data
     */
    private List<CloudResourceInstancePO> orgInstanceData;

    /**
     * Cloud account ID
     */
    private String cloudAccountId;


    private ResourceMergerTask() {

    }

    private ResourceMergerTask(List<LinkDataParam> linkedDataList, List<CloudResourceInstancePO> orgInstanceData, String cloudAccountId) {
        this.linkedDataList = linkedDataList;
        this.orgInstanceData = orgInstanceData;
        this.cloudAccountId = cloudAccountId;
    }

    public static List<CloudResourceInstancePO> mergeJsonWithTimeOut(List<LinkDataParam> linkedDataList, List<CloudResourceInstancePO> orgInstanceData, String cloudAccountId) {
        Callable<List<CloudResourceInstancePO>> task = () -> {
            try {
                ResourceMergerTask resourceMergerTask = new ResourceMergerTask(linkedDataList, orgInstanceData, cloudAccountId);
                return resourceMergerTask.call();
            } catch (Exception e) {
                throw new RuntimeException("Task was interrupted", e);
            }
        };

        try {
            // Execute the task with a timeout of 30 seconds and get the result
            return TaskExecutor.executeWithTimeout(task, MAX_TIME_OUT_MILLISECONDS);
        } catch (TimeoutException | InterruptedException | ExecutionException e) {
            log.error("Task execution failed", e);
        }

        // Return original data after timeout
        return orgInstanceData;
    }

    public static List<CloudResourceInstancePO> mergeJson(List<LinkDataParam> linkedDataList, List<CloudResourceInstancePO> orgInstanceData, String cloudAccountId) {
        Callable<List<CloudResourceInstancePO>> task = () -> {
            try {
                ResourceMergerTask resourceMergerTask = new ResourceMergerTask(linkedDataList, orgInstanceData, cloudAccountId);
                return resourceMergerTask.call();
            } catch (Exception e) {
                throw new RuntimeException("Task was interrupted", e);
            }
        };

        try {
            return TaskExecutor.execute(task);
        } catch (InterruptedException | ExecutionException e) {
            log.error("Task execution failed", e);
        }

        return orgInstanceData;
    }

    // TODO There may be performance problems when large data volume.
    @Override
    public List<CloudResourceInstancePO> call() {
        if (orgInstanceData.isEmpty()) {
            return orgInstanceData;
        }
        if (linkedDataList == null || linkedDataList.isEmpty()) {
            return orgInstanceData;
        }

        try {
            Configuration config = Configuration.defaultConfiguration();
            for (LinkDataParam linkedData : linkedDataList) {
                // Check if linkedData and its resourceType are valid
                if (linkedData == null || linkedData.getResourceType() == null || linkedData.getResourceType().size() < 2) {
                    log.warn("Invalid linkedData or resourceType, skipping this linkedData");
                    continue;
                }
                
                IQueryResource iQueryResource = SpringUtils.getApplicationContext().getBean(IQueryResource.class);
                List<CloudResourceInstancePO> cloudResourceInstancePOS = iQueryResource.queryByCond(orgInstanceData.get(0).getPlatform(), linkedData.getResourceType().get(1), cloudAccountId);
                linkedData.setDataList(cloudResourceInstancePOS);
            }

            // Turn on concurrent task
            orgInstanceData.parallelStream().forEach(instance -> {
                try {
                    log.info("resourceId {} start query...", instance.getResourceId());
                    DocumentContext context = JsonPath.using(config).parse(instance.getInstance());
                    for (LinkDataParam linkedData : linkedDataList) {
                        // Check if linkedData is valid
                        if (linkedData == null) {
                            log.warn("linkedData is null, skipping");
                            continue;
                        }
                        
                        // 读取出的值与另一个资产读取的值对比
                        List<Object> newArrayData = new ArrayList<>();
                        Object newObjData = null;

                        // Safe comparison for associativeMode
                        String associativeMode = linkedData.getAssociativeMode();
                        if (Objects.equals(associativeMode, AssociativeMode.MANY_TO_ONE.getName())) {
                            // 无关联字段，直接将关联资产挂载到主资产上
                            List<CloudResourceInstancePO> dataList = linkedData.getDataList();
                            if (CollectionUtils.isNotEmpty(dataList) && dataList.get(0) != null && dataList.get(0).getInstance() != null) {
                                newObjData = JSON.parseObject(dataList.get(0).getInstance());
                            }
                        } else {
                            // Check linkedKey1 is not null
                            String linkedKey1 = linkedData.getLinkedKey1();
                            if (linkedKey1 == null) {
                                log.warn("linkedKey1 is null, skipping");
                                continue;
                            }
                            
                            Object primaryDataValue;
                            try {
                                primaryDataValue = context.read(linkedKey1);
                            } catch (Exception e) {
                                log.warn("primaryDataValue is null, linkedKey:{}", linkedKey1, e);
                                continue;
                            }

                            // Check if dataList is valid
                            List<CloudResourceInstancePO> dataList = linkedData.getDataList();
                            if (dataList == null) {
                                log.warn("dataList is null, skipping");
                                continue;
                            }
                            
                            for (CloudResourceInstancePO linkedInstance : dataList) {
                                // Check if linkedInstance and its instance are valid
                                if (linkedInstance == null || linkedInstance.getInstance() == null) {
                                    log.warn("linkedInstance or its instance is null, skipping");
                                    continue;
                                }
                                Object linkedDocument = Configuration.defaultConfiguration().jsonProvider()
                                        .parse(linkedInstance.getInstance());

                                // Check linkedKey2 is not null
                                String linkedKey2 = linkedData.getLinkedKey2();
                                if (linkedKey2 == null) {
                                    log.warn("linkedKey2 is null, skipping");
                                    continue;
                                }
                                
                                Object linkedDataValue;
                                try {
                                    linkedDataValue = JsonPath.read(linkedDocument, linkedKey2);
                                } catch (Exception e) {
                                    log.warn("linkedDataValue is null, linkedKey:{}", linkedKey2, e);
                                    continue;
                                }
                                
                                // Check if linkedDataValue is null
                                if (linkedDataValue == null) {
                                    log.warn("linkedDataValue is null, skipping");
                                    continue;
                                }

                                if (primaryDataValue instanceof List) {
                                    // 将 primaryDataValue 转化为数组 并比较 linkedDataValue 的值是否包含在数组中
                                    List<String> primaryDataValueList = (List<String>) primaryDataValue;
                                    if (primaryDataValueList.isEmpty()) {
                                        break;
                                    }
                                    String linkedDataValueStr = String.valueOf(linkedDataValue);
                                    if (primaryDataValueList.contains(linkedDataValueStr)) {
                                        // 如果包含在数组中则创建一个新的数组，并将 linkedInstance.getInstance() 的json放到新数组后，拼接到
                                        // instance.getInstance() 中
                                        newArrayData.add(JSON.parseObject(linkedInstance.getInstance()));
                                        // 全部数据都关联完成则跳出循环
                                        if (newArrayData.size() == primaryDataValueList.size()) {
                                            break;
                                        }
                                    }
                                } else {
                                    // 直接比较 primaryDataValue 是否与 linkedDataValue 相等
                                    // 如果相等则将 linkedInstance.getInstance() 做为一个对象拼接到 instance.getInstance() 中
                                    String primaryDataValueStr = String.valueOf(primaryDataValue);
                                    String linkedDataValueStr = String.valueOf(linkedDataValue);
                                    boolean equals = primaryDataValueStr.equals(linkedDataValueStr);
                                    if (Objects.equals(associativeMode, AssociativeMode.ONE_TO_ONE.getName())) {
                                        if (equals) {
                                            newObjData = JSON.parseObject(linkedInstance.getInstance());
                                            break;
                                        }
                                    } else {
                                        if (equals) {
                                            newArrayData.add(JSON.parseObject(linkedInstance.getInstance()));
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        boolean filled = false;
                        // Check if newKeyName is valid
                        String newKeyName = linkedData.getNewKeyName();
                        if (newKeyName == null) {
                            log.warn("newKeyName is null, skipping");
                            continue;
                        }
                        
                        // array
                        Map<String, Object> map = context.json();
                        if (!newArrayData.isEmpty()) {
                            map.put(newKeyName, newArrayData);
                            filled = true;
                        }

                        // obj
                        if (newObjData != null) {
                            map.put(newKeyName, newObjData);
                            filled = true;
                        }

                        if (!filled) {
                            map.put(newKeyName, null);
                        }

                        instance.setInstance(JSON.toJSONString(map, SerializerFeature.WriteMapNullValue));

                    }

                    log.info("resourceId {} end query !!!", instance.getResourceId());
                } catch (Exception e) {
                    List<String> list = linkedDataList.stream().map(LinkDataParam::getLinkedKey1).toList();
                    List<String> list2 = linkedDataList.stream().map(LinkDataParam::getLinkedKey2).toList();
                    log.error("resource mergeJson error,linkedKey1:{} linkedKey2:{} resourceId:{}", list, list2, instance.getResourceId(), e);
                }
            });
        } catch (Exception e) {
            log.error("resource mergeJson error", e);
        }

        return orgInstanceData;
    }

}
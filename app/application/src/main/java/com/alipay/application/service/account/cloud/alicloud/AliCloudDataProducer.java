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
package com.alipay.application.service.account.cloud.alicloud;


import com.alipay.application.service.account.cloud.DataProducer;
import com.alipay.application.service.account.cloud.Producer;
import com.alipay.application.service.account.domain.SecurityProductPosture;
import com.alipay.application.service.account.enums.SecurityProductStatus;
import com.alipay.application.service.account.enums.SecurityProductType;
import com.alipay.application.service.resource.IQueryResource;
import com.alipay.common.enums.AclStatus;
import com.alipay.common.enums.CloudRamUserType;
import com.alipay.common.enums.PlatformType;
import com.alipay.common.utils.JsonPathUtils;
import com.alipay.common.utils.JsonUtils;
import com.alipay.dao.dto.IQueryResourceDTO;
import com.alipay.dao.mapper.CloudRamMapper;
import com.alipay.dao.mapper.RuleScanResultMapper;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.CloudRamPO;
import com.alipay.dao.po.CloudResourceInstancePO;
import com.alipay.dao.po.RuleScanResultPO;
import jakarta.annotation.Resource;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

/*
 *@title AliCloudSecurityDataProducer
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/4/10 16:51
 */
@Component
public class AliCloudDataProducer extends Producer implements DataProducer {

    @Resource
    private CloudRamMapper cloudRamMapper;

    @Resource
    private IQueryResource iQueryResource;

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    private static final String platform = PlatformType.Enum.ALI_CLOUD;

    /**
     * 加工 iam 身份统计数据
     */
    @Override
    public void productIamStatisticsData() {
        boolean success = super.deleteRamAclData(platform);
        if (!success){
            return;
        }

        List<CloudAccountPO> cloudAccountList = super.getCloudAccountList(platform);
        for (CloudAccountPO cloudAccountPO : cloudAccountList) {
            List<CloudResourceInstancePO> cloudResourceInstancePOS = iQueryResource.queryByCond(platform, "RAM User", cloudAccountPO.getCloudAccountId());
            for (CloudResourceInstancePO cloudResourceInstancePO : cloudResourceInstancePOS) {
                CloudRamPO cloudRamPO = new CloudRamPO();
                cloudRamPO.setPlatform(cloudResourceInstancePO.getPlatform());
                cloudRamPO.setCloudAccountId(cloudResourceInstancePO.getCloudAccountId());
                cloudRamPO.setAlias(cloudResourceInstancePO.getAlias());
                cloudRamPO.setUserId(cloudResourceInstancePO.getResourceId());
                cloudRamPO.setUserName(cloudResourceInstancePO.getResourceName());
                cloudRamPO.setDetail(cloudResourceInstancePO.getInstance());
                cloudRamPO.setTenantId(cloudResourceInstancePO.getTenantId());

                // Analyze the number of ak
                int akNum = JsonUtils.getFieldSize(cloudResourceInstancePO.getInstance(), "AccessKeys");
                cloudRamPO.setAkNum(akNum);
                cloudRamPO.setUserType(CloudRamUserType.not_main.getType());

                // Determine permission status
                // ruleName:AK未设置调用来源ACL
                RuleScanResultPO RuleScanResultPO = ruleScanResultMapper.findOneJoinRule(cloudResourceInstancePO.getResourceId(), cloudResourceInstancePO.getCloudAccountId(), "ALI_CLOUD_RAM User_202504031734_497143");
                if (RuleScanResultPO != null) {
                    cloudRamPO.setAclStatus(AclStatus.not_exist_acl.getStatus());
                } else {
                    cloudRamPO.setAclStatus(AclStatus.exist_acl.getStatus());
                }
                cloudRamMapper.insertSelective(cloudRamPO);
            }
        }
    }


    /**
     * 加工阿里云安全产品统计数据
     */
    @Override
    public void productSecurityProductStatisticsData() {
        List<CloudAccountPO> cloudAccountList = super.getCloudAccountList(platform);
        List<String> securityProductList = SecurityProductType.getSecurityProductList(platform);
        for (CloudAccountPO cloudAccountPO : cloudAccountList) {
            for (String securityProduct : securityProductList) {
                if (Objects.equals(SecurityProductType.AliyunSecurityProductType.SAS.getCode(), securityProduct)) {
                    IQueryResourceDTO request = IQueryResourceDTO.builder()
                            .resourceType(SecurityProductType.AliyunSecurityProductType.SAS.getRelatedResourceType())
                            .cloudAccountId(cloudAccountPO.getCloudAccountId())
                            .size(1)
                            .build();

                    CloudResourceInstancePO cloudResourceInstancePO = iQueryResource.queryResource(request);
                    if (cloudResourceInstancePO == null) {
                        SecurityProductPosture securityProductPosture = SecurityProductPosture.defaultSecurityProductPosture(cloudAccountPO, securityProduct, SecurityProductType.AliyunSecurityProductType.SAS.getRelatedResourceType());
                        super.saveSecurityProductPosture(securityProductPosture);
                        continue;
                    }

                    String version = JsonPathUtils.getValue(cloudResourceInstancePO.getInstance(), "$.AuthSummary.HighestVersion", String.class);
                    String versionDesc = SecurityProductType.AliyunSecurityProductType.getSasVersionDescription(version);

                    SecurityProductPosture securityProductPosture = SecurityProductPosture.builder().cloudAccountPO(cloudAccountPO)
                            .productType(securityProduct)
                            .resourceType(SecurityProductType.AliyunSecurityProductType.SAS.getRelatedResourceType())
                            .status(SecurityProductStatus.open.name())
                            .version(version)
                            .versionDesc(versionDesc)
                            .policy("已开通" + versionDesc)
                            .policyDetail(cloudResourceInstancePO.getInstance())
                            .protectedCount(JsonPathUtils.getValue(cloudResourceInstancePO.getInstance(), "$.AuthSummary.Machine.BindEcsCount", Integer.class))
                            .total(JsonPathUtils.getValue(cloudResourceInstancePO.getInstance(), "$.AuthSummary.Machine.TotalEcsCount", Integer.class))
                            .build();

                    super.saveSecurityProductPosture(securityProductPosture);

                } else if (Objects.equals(SecurityProductType.AliyunSecurityProductType.DDOS.getCode(), securityProduct)) {
                    IQueryResourceDTO request = IQueryResourceDTO.builder()
                            .resourceType(SecurityProductType.AliyunSecurityProductType.DDOS.getRelatedResourceType())
                            .cloudAccountId(cloudAccountPO.getCloudAccountId())
                            .size(1)
                            .build();
                    CloudResourceInstancePO cloudResourceInstancePO = iQueryResource.queryResource(request);
                    if (cloudResourceInstancePO == null) {
                        SecurityProductPosture securityProductPosture = SecurityProductPosture.defaultSecurityProductPosture(cloudAccountPO, securityProduct, SecurityProductType.AliyunSecurityProductType.DDOS.getRelatedResourceType());
                        super.saveSecurityProductPosture(securityProductPosture);
                        continue;
                    }
                    String version = JsonPathUtils.getValue(cloudResourceInstancePO.getInstance(), "$.Instance.Edition", String.class);
                    String versionDesc = SecurityProductType.AliyunSecurityProductType.getDdosVersionDescription(version);

                    SecurityProductPosture securityProductPosture = SecurityProductPosture.builder().cloudAccountPO(cloudAccountPO)
                            .productType(securityProduct)
                            .resourceType(SecurityProductType.AliyunSecurityProductType.DDOS.getRelatedResourceType())
                            .status(SecurityProductStatus.open.name())
                            .version(version)
                            .versionDesc(versionDesc)
                            .policy("已开通" + versionDesc)
                            .policyDetail(cloudResourceInstancePO.getInstance())
                            .protectedCount(0)
                            .total(0)
                            .build();
                    super.saveSecurityProductPosture(securityProductPosture);

                } else if (Objects.equals(SecurityProductType.AliyunSecurityProductType.WAF.getCode(), securityProduct)) {
                    IQueryResourceDTO request = IQueryResourceDTO.builder()
                            .resourceType(SecurityProductType.AliyunSecurityProductType.WAF.getRelatedResourceType())
                            .cloudAccountId(cloudAccountPO.getCloudAccountId())
                            .size(1)
                            .build();

                    CloudResourceInstancePO cloudResourceInstancePO = iQueryResource.queryResource(request);
                    if (cloudResourceInstancePO == null) {
                        SecurityProductPosture securityProductPosture = SecurityProductPosture.defaultSecurityProductPosture(cloudAccountPO, securityProduct, SecurityProductType.AliyunSecurityProductType.WAF.getRelatedResourceType());
                        super.saveSecurityProductPosture(securityProductPosture);
                        continue;
                    }
                    String version = JsonPathUtils.getValue(cloudResourceInstancePO.getInstance(), "$.Instance.Edition", String.class);
                    SecurityProductPosture securityProductPosture = SecurityProductPosture.builder().cloudAccountPO(cloudAccountPO)
                            .productType(securityProduct)
                            .resourceType(SecurityProductType.AliyunSecurityProductType.DDOS.getRelatedResourceType())
                            .status(SecurityProductStatus.open.name())
                            .version(version)
                            .versionDesc(version)
                            .policy("已开通" + version)
                            .policyDetail(cloudResourceInstancePO.getInstance())
                            .protectedCount(0)
                            .total(0)
                            .build();
                    super.saveSecurityProductPosture(securityProductPosture);

                } else if (Objects.equals(SecurityProductType.AliyunSecurityProductType.FIREWALL.getCode(), securityProduct)) {
                    IQueryResourceDTO request = IQueryResourceDTO.builder()
                            .resourceType(SecurityProductType.AliyunSecurityProductType.FIREWALL.getRelatedResourceType())
                            .cloudAccountId(cloudAccountPO.getCloudAccountId())
                            .size(1)
                            .build();

                    CloudResourceInstancePO cloudResourceInstancePO = iQueryResource.queryResource(request);
                    if (cloudResourceInstancePO == null) {
                        SecurityProductPosture securityProductPosture = SecurityProductPosture.defaultSecurityProductPosture(cloudAccountPO, securityProduct, SecurityProductType.AliyunSecurityProductType.FIREWALL.getRelatedResourceType());
                        super.saveSecurityProductPosture(securityProductPosture);
                        continue;
                    }

                    String version = JsonPathUtils.getValue(cloudResourceInstancePO.getInstance(), "$.CloudfwVersionInfo.Version", String.class);
                    String versionDesc = SecurityProductType.AliyunSecurityProductType.getCloudfwVersionDescription(version);
                    SecurityProductPosture securityProductPosture = SecurityProductPosture.builder().cloudAccountPO(cloudAccountPO)
                            .productType(securityProduct)
                            .resourceType(SecurityProductType.AliyunSecurityProductType.FIREWALL.getRelatedResourceType())
                            .status(SecurityProductStatus.open.name())
                            .version(version)
                            .versionDesc(versionDesc)
                            .policy("已开通" + versionDesc)
                            .policyDetail(cloudResourceInstancePO.getInstance())
                            .protectedCount(0)
                            .total(0)
                            .build();
                    super.saveSecurityProductPosture(securityProductPosture);
                }
            }
        }
    }
}

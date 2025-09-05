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
package com.alipay.application.share.vo.account;

import com.alipay.application.service.account.utils.PlatformUtils;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.application.service.resource.IQueryResource;
import com.alipay.application.service.risk.RiskStatusManager;
import com.alipay.common.constant.CollectorStatusConstants;
import com.alipay.common.enums.Status;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.mapper.PlatformMapper;
import com.alipay.dao.mapper.ResourceMapper;
import com.alipay.dao.mapper.RuleScanResultMapper;
import com.alipay.dao.mapper.TenantMapper;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.PlatformPO;
import com.alipay.dao.po.ResourcePO;
import com.alipay.dao.po.TenantPO;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Data
public class CloudAccountVO {

    private Long id;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtCreate;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtModified;

    /**
     * 云账号id
     */
    private String cloudAccountId;

    /**
     * 云账号别名
     */
    private String alias;

    /**
     * 平台标识
     */
    private String platform;

    /**
     * 平台名称
     */
    private String platformName;

    /**
     * 状态
     */
    private String status;

    /**
     * 租户id
     */
    private Long tenantId;

    /**
     * 租户名称
     */
    private String tenantName;

    /**
     * 修改租户权限
     */
    private Boolean changeTenantPermission;

    /**
     * 资产数
     */
    private Long resourceCount;

    /**
     * 风险数
     */
    private Integer riskCount;

    /**
     * 最近扫描时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date lastScanTime;

    /**
     * 资源类型列表（包含资源组）
     */
    private List<List<String>> resourceTypeListForWeb;

    /**
     * 采集器状态
     */
    private String collectorStatus;

    /**
     * 云账号状态：启用/禁用
     */
    private String accountStatus;


    private Map<String, String> credentialMap;

    /**
     * 部署站点
     */
    private String site;

    private String owner;

    private String userId;

    /**
     * 代理配置JSON
     */
    private String proxyConfig;

    private String email;

    private Boolean enableInverseSelection;


    public static CloudAccountVO buildEasy(CloudAccountPO cloudAccountPO) {
        if (cloudAccountPO == null) {
            return null;
        }
        CloudAccountVO cloudAccountVO = new CloudAccountVO();
        BeanUtils.copyProperties(cloudAccountPO, cloudAccountVO, "credentialMap");
        cloudAccountVO.setEnableInverseSelection(cloudAccountPO.getEnableInverseSelection() == 1);


        if (cloudAccountPO.getTenantId() != null) {
            TenantMapper tenantMapper = SpringUtils.getBean(TenantMapper.class);
            TenantPO tenantPO = tenantMapper.selectByPrimaryKey(cloudAccountPO.getTenantId());
            if (tenantPO != null) {
                cloudAccountVO.setTenantName(tenantPO.getTenantName());
            }
        }
        return cloudAccountVO;
    }

    public static CloudAccountVO build(CloudAccountPO cloudAccountPO) {
        if (cloudAccountPO == null) {
            return null;
        }

        CloudAccountVO cloudAccountVO = new CloudAccountVO();
        BeanUtils.copyProperties(cloudAccountPO, cloudAccountVO);

        // Query credential info
        if (StringUtils.isNoneEmpty(cloudAccountPO.getCredentialsJson())) {
            Map<String, String> accountCredentialsInfo = PlatformUtils.getAccountCredentialsInfo(cloudAccountPO.getPlatform(), PlatformUtils.decryptCredentialsJson(cloudAccountPO.getCredentialsJson()));
            cloudAccountVO.setCredentialMap(PlatformUtils.ignoreSensitiveInfo(accountCredentialsInfo));
        }

        // Query resource quantity
        long resourceCount = SpringUtils.getBean(IQueryResource.class).queryResourceCount(cloudAccountPO.getCloudAccountId());
        cloudAccountVO.setResourceCount(resourceCount);

        // Query risk count
        RuleScanResultDTO dto = RuleScanResultDTO.builder().cloudAccountId(cloudAccountPO.getCloudAccountId()).status(RiskStatusManager.RiskStatus.UNREPAIRED.name()).build();
        int riskCount = SpringUtils.getBean(RuleScanResultMapper.class).findCount(dto);
        cloudAccountVO.setRiskCount(riskCount);

        // Query platform name
        PlatformPO platformPO = SpringUtils.getBean(PlatformMapper.class).findByPlatform(cloudAccountPO.getPlatform());
        if (platformPO != null) {
            cloudAccountVO.setPlatformName(platformPO.getPlatformName());
        }

        // Asset types supported for scanning
        cloudAccountVO.setEnableInverseSelection(cloudAccountPO.getEnableInverseSelection() == 1);
        if (cloudAccountPO.getResourceTypeList() != null) {
            String[] split = cloudAccountPO.getResourceTypeList().split(",");
            List<List<String>> list = Arrays.stream(split).parallel()
                    .map(e -> queryResource(cloudAccountPO.getPlatform(), e)).toList();
            cloudAccountVO.setResourceTypeListForWeb(list);
        }


        cloudAccountVO.setCollectorStatus(Status.running.name().equals(cloudAccountPO.getCollectorStatus()) ? CollectorStatusConstants.running : CollectorStatusConstants.waiting);

        if (cloudAccountPO.getTenantId() != null) {
            TenantMapper tenantMapper = SpringUtils.getBean(TenantMapper.class);
            TenantPO tenantPO = tenantMapper.selectByPrimaryKey(cloudAccountPO.getTenantId());
            if (tenantPO != null) {
                cloudAccountVO.setTenantName(tenantPO.getTenantName());
            }
        }

        return cloudAccountVO;
    }

    private static List<String> queryResource(String platform, String resourceType) {
        ResourceMapper resourceMapper = SpringUtils.getApplicationContext().getBean(ResourceMapper.class);
        ResourcePO resourcePO = resourceMapper.findOne(platform, resourceType);
        if (resourcePO != null) {
            return Arrays.asList(resourcePO.getResourceGroupType(), resourcePO.getResourceType());
        }

        return List.of();
    }
}
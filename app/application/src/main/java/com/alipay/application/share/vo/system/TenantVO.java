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
package com.alipay.application.share.vo.system;

import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.common.constant.TenantConstants;
import com.alipay.dao.po.TenantPO;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import org.springframework.beans.BeanUtils;

import java.util.Date;

@Data
public class TenantVO {

    private Long id;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtCreate;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtModified;

    /**
     * 租户名称
     */
    private String tenantName;

    /**
     * 租户状态
     */
    private String status;

    /**
     * 租户描述
     */
    private String tenantDesc;

    /**
     * 成员数量
     */
    private Integer memberCount;

    
    private Boolean disable;

    public static TenantVO toVO(TenantPO tenant) {
        if (tenant == null) {
            return null;
        }

        TenantVO tenantVO = new TenantVO();
        BeanUtils.copyProperties(tenant, tenantVO);

        TenantRepository tenantRepository = SpringUtils.getBean(TenantRepository.class);
        int count = tenantRepository.memberCount(tenant.getId());
        tenantVO.setMemberCount(count);

        // Set disable flag based on whether tenant is a system default tenant
        if (TenantConstants.SYSTEN_DEFAULT_TENANT_LIST.contains(tenant.getTenantName())){
            tenantVO.setDisable(true);
        } else {
            tenantVO.setDisable(false);
        }

        return tenantVO;
    }
}
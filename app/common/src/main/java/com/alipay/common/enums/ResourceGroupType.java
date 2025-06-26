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
package com.alipay.common.enums;

import lombok.Getter;
import org.springframework.context.i18n.LocaleContextHolder;

import java.util.Locale;

/*
 *@title ResourceGroupType
 *@description Enumeration of resource group types
 *@author jietian
 *@version 1.0
 *@create 2024/8/30 12:09
 */
@Getter
public enum ResourceGroupType {

    // 格式：常量名, 中文名, 图标路径, 国际化术语（新增）
    UNKNOWN("UNKNOWN", "未知", "", "Undefined"),
    NET("NET", "网络", "icon/net.svg", "Network"),
    CONTAINER("CONTAINER", "容器", "icon/container.svg", "Container"),
    DATABASE("DATABASE", "数据库", "icon/database.svg", "Database"),
    STORE("STORE", "存储", "icon/store.svg", "Storage"),
    COMPUTE("COMPUTE", "计算", "icon/compute.svg", "Compute"),
    IDENTITY("IDENTITY", "身份", "icon/identity.svg", "Identity"),
    CONFIG("CONFIG", "配置", "icon/config.svg", "Configuration"),
    SECURITY("SECURITY", "安全产品", "icon/security.svg", "Security Products"),
    AI("AI", "AI", "icon/AI.svg", "AI"),
    MIDDLEWARE("MIDDLEWARE", "中间件", "icon/middleware.svg", "Middleware"),
    BIGDATA("BIGDATA", "大数据", "icon/bigdata.svg", "Big Data"),
    LOG("LOG", "日志", "icon/log.svg", "Logging"),
    GOVERNANCE("GOVERNANCE", "管理", "icon/governance.svg", "Governance");

    private final String code;
    private final String desc;
    private final String icon;
    private final String descEn;

    ResourceGroupType(String code, String desc, String icon, String descEn) {
        this.code = code;
        this.desc = desc;
        this.icon = icon;
        this.descEn = descEn;
    }

    public static ResourceGroupType getByCode(String code) {
        for (ResourceGroupType type : values()) {
            if (type.getCode().equals(code)) {
                return type;
            }
        }
        return UNKNOWN;
    }

    public static String getDescByCode(String code) {
        Locale locale = LocaleContextHolder.getLocale();

        String desc = "";
        for (ResourceGroupType type : values()) {
            if (type.getCode().equals(code)) {
                if (locale.getLanguage().equals(Locale.CHINA.getLanguage())) {
                    desc = type.getDesc();
                } else {
                    desc = type.getDescEn();
                }
            }
        }

        if (desc.isEmpty()) {
            desc = UNKNOWN.getDesc();
        }

        return desc;
    }
}

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
package com.alipay.application.service.common;


import com.alipay.common.enums.PlatformType;
import com.alipay.dao.mapper.PlatformMapper;
import com.alipay.dao.po.PlatformPO;
import jakarta.annotation.Resource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/*
 *@title Platform
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/2/27 18:28
 */
@Component
public class Platform {

    @Resource
    private PlatformMapper platformMapper;

    public List<PlatformPO> queryPlatformList() {
        List<PlatformPO> platformPOS = platformMapper.findAll();

        List<PlatformPO> list = platformPOS.stream()
                .sorted((p1, p2) -> {
                    if (p1.getPlatform().equals(PlatformType.ALI_CLOUD_PRIVATE.getPlatform()) || p1.getPlatform().equals(PlatformType.HUAWEI_CLOUD_PRIVATE.getPlatform())) {
                        return 1;
                    }
                    if (p2.getPlatform().equals(PlatformType.ALI_CLOUD_PRIVATE.getPlatform()) || p2.getPlatform().equals(PlatformType.HUAWEI_CLOUD_PRIVATE.getPlatform())) {
                        return -1;
                    }
                    return p1.getPlatform().compareToIgnoreCase(p2.getPlatform());
                })
                .toList();

        return list.stream().peek(p -> {
            p.setPlatformName(getPlatformName(p.getPlatform()));
        }).toList();
    }

    public static String getPlatformName(String type) {
        Locale locale = LocaleContextHolder.getLocale();
        if (locale.getLanguage().equals(Locale.CHINA.getLanguage())) {
            return PlatformType.getPlatformType(type).getCnName();
        } else {
            return PlatformType.getPlatformType(type).getEnName();
        }
    }

    public static List<String> getPlatformNameList(PlatformType... type) {
        return Arrays.stream(type).map(t -> getPlatformName(t.getPlatform())).toList();
    }
}

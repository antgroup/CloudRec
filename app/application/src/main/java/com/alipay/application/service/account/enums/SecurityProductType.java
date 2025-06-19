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
package com.alipay.application.service.account.enums;


import com.alipay.common.enums.PlatformType;
import com.alipay.common.exception.BizException;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/*
 *@title SecurityProductType
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/4/10 11:10
 */
public class SecurityProductType {

    public static List<String> getSupportedPlatformList() {
        return List.of(PlatformType.Enum.ALI_CLOUD, PlatformType.Enum.GCP, PlatformType.Enum.KINGSOFT_CLOUD);
    }

    public static final String unknown = "unknown";


    /**
     * 获取指定平台的安全产品列表
     */
    public static List<String> getSecurityProductList(String platform) {
        if (PlatformType.Enum.ALI_CLOUD.equals(platform)) {
            return Arrays.stream(AliyunSecurityProductType.values()).map(AliyunSecurityProductType::getCode).toList();
        } else if (PlatformType.Enum.AWS.equals(platform)) {
            return Arrays.stream(AwsSecurityProductType.values()).map(AwsSecurityProductType::getCode).toList();
        } else if (PlatformType.Enum.GCP.equals(platform)) {
            return Arrays.stream(GCPSecurityProductType.values()).map(GCPSecurityProductType::getCode).toList();
        } else if (PlatformType.Enum.KINGSOFT_CLOUD.equals(platform)) {
            return Arrays.stream(KingsoftCloudSecurityProductType.values()).map(KingsoftCloudSecurityProductType::getCode).toList();
        }

        // ...
        throw new BizException("暂不支持该平台的安全管控数据");
    }


    /**
     * 阿里云安全产品类型枚举
     */
    @Getter
    @AllArgsConstructor
    public enum AliyunSecurityProductType {
        DDOS("DDoS", "DDoS 高防", "DdosCoo"),
        WAF("WAF", "WAF", "WAF"),
        FIREWALL("FIRE WALL", "防火墙", "Cloudfw Config"),
        SAS("SAS", "云安全中心", "Sas Config");

        private final String code;
        private final String desc;
        private final String relatedResourceType;

        public static AliyunSecurityProductType getByCode(String code) {
            for (AliyunSecurityProductType value : values()) {
                if (value.getCode().equals(code)) {
                    return value;
                }
            }
            throw new BizException("暂不支持该产品类型");
        }

        public static String getSasVersionDescription(String version) {
            String versionDesc = unknown;
            if (Objects.equals("1", version)) {
                versionDesc = "免费版";
            } else if (Objects.equals("3", version)) {
                versionDesc = "企业版";
            } else if (Objects.equals("5", version)) {
                versionDesc = "高级版";
            } else if (Objects.equals("6", version)) {
                versionDesc = "防病毒版";
            } else if (Objects.equals("7", version)) {
                versionDesc = "旗舰版";
            } else if (Objects.equals("8", version)) {
                versionDesc = "多版本";
            } else if (Objects.equals("10", version)) {
                versionDesc = "仅采购增值服务";
            }

            return versionDesc;
        }

        // 云防火墙实例的版本信息。取值：
        //
        //2：高级版
        //3：企业版
        //4：旗舰版
        //10：按量付费版本
        public static String getCloudfwVersionDescription(String version) {
            String versionDesc = unknown;
            if (Objects.equals("2", version)) {
                versionDesc = "高级版";
            } else if (Objects.equals("3", version)) {
                versionDesc = "企业版";
            } else if (Objects.equals("4", version)) {
                versionDesc = "旗舰版";
            } else if (Objects.equals("10", version)) {
                versionDesc = "按量付费版本";
            }

            return versionDesc;
        }

        // 实例的防护套餐版本。取值：
        //
        //0：表示 DDoS 高防（非中国内地）保险版。
        //1：表示 DDoS 高防（非中国内地）无忧版。
        //2： 表示 DDoS 高防（非中国内地）加速线路。
        //9：表示 DDoS 高防（中国内地）专业版。
        public static String getDdosVersionDescription(String version) {
            String versionDesc = unknown;
            if (Objects.equals("0", version)) {
                versionDesc = "DDoS 高防（非中国内地）保险版";
            } else if (Objects.equals("1", version)) {
                versionDesc = "DDoS 高防（非中国内地）无忧版";
            } else if (Objects.equals("2", version)) {
                versionDesc = "DDoS 高防（非中国内地）加速线路";
            } else if (Objects.equals("9", version)) {
                versionDesc = "DDoS 高防（中国内地）专业版";
            }

            return versionDesc;
        }
    }

    /**
     * AWS安全产品类型枚举
     */
    @Getter
    @AllArgsConstructor
    public enum AwsSecurityProductType {
        FIREWALL("FIRE WALL", "防火墙", "FIREWALL"),
        WAF("WAF", "WAF", "WAF");
        private final String code;
        private final String desc;
        private final String relatedResourceType;

        public static AwsSecurityProductType getByCode(String code) {
            for (AwsSecurityProductType value : values()) {
                if (value.getCode().equals(code)) {
                    return value;
                }
            }
            throw new BizException("暂不支持该产品类型");
        }
    }

    /**
     * GCP安全产品类型枚举
     */
    @Getter
    @AllArgsConstructor
    public enum GCPSecurityProductType {
        FIREWALL("FIRE WALL", "防火墙", "FIREWALL"),
        WAF("WAF", "WAF", "WAF");
        private final String code;
        private final String desc;
        private final String relatedResourceType;

        public static GCPSecurityProductType getByCode(String code) {
            for (GCPSecurityProductType value : values()) {
                if (value.getCode().equals(code)) {
                    return value;
                }
            }
            throw new BizException("暂不支持该产品类型");
        }
    }

    /**
     * KINGSOFT_CLOUD安全产品类型枚举
     */
    @Getter
    @AllArgsConstructor
    public enum KingsoftCloudSecurityProductType {
        DDOS("DDoS", "DDoS 高防", "KNAD"),
        FIREWALL("FIRE WALL", "防火墙", "FIREWALL"),
        WAF("WAF", "WAF", "WAF");
        private final String code;
        private final String desc;
        private final String relatedResourceType;

        public static KingsoftCloudSecurityProductType getByCode(String code) {
            for (KingsoftCloudSecurityProductType value : values()) {
                if (value.getCode().equals(code)) {
                    return value;
                }
            }
            throw new BizException("暂不支持该产品类型");
        }
    }
}

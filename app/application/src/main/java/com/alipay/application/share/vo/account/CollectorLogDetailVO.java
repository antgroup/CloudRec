package com.alipay.application.share.vo.account;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class CollectorLogDetailVO {


    /*
     * 云账号id
     */
    private String cloudAccountId;

    /*
     * 云账号别名
     */
    private String alias;

    /*
     * 云平台
     */
    private String platform;


    /**
     * 错误详情列表
     */
    private List<ErrorDetail> errorDetails;


    public static class ErrorDetail {

        /*
         * 发生错误的资产类型
         */
        private String resourceType;

        private String resourceTypeName;

        /**
         * 错误详情列表
         */
        private List<ErrorDetailItem> errorDetailItems;

        public String getResourceType() {
            return resourceType;
        }

        public void setResourceType(String resourceType) {
            this.resourceType = resourceType;
        }

        public List<ErrorDetailItem> getErrorDetailItems() {
            return errorDetailItems;
        }

        public void setErrorDetailItems(List<ErrorDetailItem> errorDetailItems) {
            this.errorDetailItems = errorDetailItems;
        }

        public String getResourceTypeName() {
            return resourceTypeName;
        }

        public void setResourceTypeName(String resourceTypeName) {
            this.resourceTypeName = resourceTypeName;
        }
    }

    /**
     * 错误详情
     */
    public static class ErrorDetailItem {
        /*
         * 错误描述
         */
        private String description;
        /*
         * 错误详细信息
         */
        private String message;
        /*
         * 发生时间
         */
        private String time;

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public String getTime() {
            return time;
        }

        public void setTime(String time) {
            this.time = time;
        }
    }
}
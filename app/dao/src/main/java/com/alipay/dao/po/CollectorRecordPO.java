package com.alipay.dao.po;

import java.util.Date;

public class CollectorRecordPO {
    private Long id;

    private Date gmtCreate;

    private Date gmtModified;

    private String platform;

    private String cloudAccountId;

    private Date startTime;

    private Date endTime;

    private String collectRecordInfo;

    private String registryValue;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Date getGmtCreate() {
        return gmtCreate;
    }

    public void setGmtCreate(Date gmtCreate) {
        this.gmtCreate = gmtCreate;
    }

    public Date getGmtModified() {
        return gmtModified;
    }

    public void setGmtModified(Date gmtModified) {
        this.gmtModified = gmtModified;
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(String platform) {
        this.platform = platform;
    }

    public String getCloudAccountId() {
        return cloudAccountId;
    }

    public void setCloudAccountId(String cloudAccountId) {
        this.cloudAccountId = cloudAccountId;
    }

    public Date getStartTime() {
        return startTime;
    }

    public void setStartTime(Date startTime) {
        this.startTime = startTime;
    }

    public Date getEndTime() {
        return endTime;
    }

    public void setEndTime(Date endTime) {
        this.endTime = endTime;
    }

    public String getRegistryValue() {
        return registryValue;
    }

    public void setRegistryValue(String registryValue) {
        this.registryValue = registryValue;
    }

    public String getCollectRecordInfo() {
        return collectRecordInfo;
    }

    public void setCollectRecordInfo(String collectRecordInfo) {
        this.collectRecordInfo = collectRecordInfo;
    }
}
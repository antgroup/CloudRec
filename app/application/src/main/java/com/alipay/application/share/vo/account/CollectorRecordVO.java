package com.alipay.application.share.vo.account;

import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.dao.mapper.CloudAccountMapper;
import com.alipay.dao.mapper.CollectorLogMapper;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.CollectorLogPO;
import com.alipay.dao.po.CollectorRecordPO;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.collections4.CollectionUtils;

import java.util.Date;
import java.util.List;

@Getter
@Setter
public class CollectorRecordVO {

    private Long id;

    /**
     * 记录创建时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtCreate;

    /**
     * 记录修改时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date gmtModified;

    /**
     * 平台
     */
    private String platform;

    /**
     * 云账号id
     */
    private String cloudAccountId;

    /**
     * 云账号别名
     */
    private String alias;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date startTime;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date endTime;

    /**
     * 采集进度：利用资产表进行计算，某一个云账号，不带有pre-delete标识/全部resource = xx%
     */
    private String percent;

    /**
     * 异常采集类型
     */
    private List<String> errorResourceTypeList;

    /**
     * 采集器的名称
     */
    private String collectorName;

    public static CollectorRecordVO build(CollectorRecordPO collectorRecordPO) {
        // 基础信息
        CollectorRecordVO collectorRecordVO = new CollectorRecordVO();
        collectorRecordVO.setId(collectorRecordPO.getId());
        collectorRecordVO.setGmtCreate(collectorRecordPO.getGmtCreate());
        collectorRecordVO.setGmtModified(collectorRecordPO.getGmtModified());
        collectorRecordVO.setPlatform(collectorRecordPO.getPlatform());
        collectorRecordVO.setCloudAccountId(collectorRecordPO.getCloudAccountId());
        collectorRecordVO.setStartTime(collectorRecordPO.getStartTime());
        collectorRecordVO.setEndTime(collectorRecordPO.getEndTime());
        collectorRecordVO.setCollectorName(collectorRecordPO.getRegistryValue());

        // 云账号别名
        CloudAccountMapper cloudAccountMapper = SpringUtils.getBean(CloudAccountMapper.class);
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(collectorRecordPO.getCloudAccountId());
        if (cloudAccountPO != null) {
            collectorRecordVO.setAlias(cloudAccountPO.getAlias());
        }

        // 异常资产数量
        CollectorLogMapper collectorLogMapper = SpringUtils.getBean(CollectorLogMapper.class);
        List<CollectorLogPO> collectorLogPOS = collectorLogMapper.findList(collectorRecordPO.getId());
        if (CollectionUtils.isNotEmpty(collectorLogPOS)) {
            List<String> errorResourceTypeList = collectorLogPOS.stream().map(CollectorLogPO::getResourceType).toList();
            collectorRecordVO.setErrorResourceTypeList(errorResourceTypeList);
        }

        return collectorRecordVO;
    }
}
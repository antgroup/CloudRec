package com.alipay.application.service.resource;


import com.alipay.dao.dto.IQueryResourceDTO;
import com.alipay.dao.mapper.CloudResourceInstanceMapper;
import com.alipay.dao.po.CloudResourceInstancePO;
import jakarta.annotation.Resource;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.Date;
import java.util.List;

/*
 *@title DelResourceServiceImpl
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/26 22:19
 */
@Service
public class DelResourceServiceImpl implements DelResourceService {

    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;

    /**
     * 分批次预删除资源，将资源的逻辑删除次数 + 1，并记录删除时间
     *
     * @param cloudAccountId 云账号id
     * @return 删除的资源数量
     */
    @Override
    public int preDeleteByCloudAccountId(String cloudAccountId) {
        int totalUpdated = 0;
        final int size = 1000;
        Long scrollId = 0L;
        while (true) {
            IQueryResourceDTO request = IQueryResourceDTO.builder()
                    .cloudAccountId(cloudAccountId)
                    .scrollId(scrollId)
                    .size(size)
                    .build();
            List<CloudResourceInstancePO> cloudResourceInstancePOS = cloudResourceInstanceMapper.findByCondWithScrollId(request);
            if (CollectionUtils.isEmpty(cloudResourceInstancePOS)) {
                break;
            } else {
                List<Long> idList = cloudResourceInstancePOS.stream().map(CloudResourceInstancePO::getId).toList();
                int effectCount = cloudResourceInstanceMapper.preDeleteByIdList(idList, new Date());
                totalUpdated += effectCount;
                if (cloudResourceInstancePOS.size() < size) {
                    break;
                }
                scrollId = cloudResourceInstancePOS.get(cloudResourceInstancePOS.size() - 1).getId();
            }
        }
        return totalUpdated;
    }
}

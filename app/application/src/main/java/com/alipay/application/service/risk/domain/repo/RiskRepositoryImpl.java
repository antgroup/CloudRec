
package com.alipay.application.service.risk.domain.repo;


import com.alipay.dao.mapper.CollectorRecordMapper;
import com.alipay.dao.mapper.RuleScanResultMapper;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

/*
 *@title RiskRepository
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/16 15:26
 */
@Slf4j
@Repository
public class RiskRepositoryImpl implements RiskRepository {

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private CollectorRecordMapper collectorRecordMapper;

    @Override
    public void remove(String cloudAccountId) {
        try {
            while (true) {
                int i = ruleScanResultMapper.deleteByCloudAccountId(cloudAccountId);
                if (i == 0) {
                    break;
                }
            }
        } catch (Exception e) {
            log.error("{} del risk error", cloudAccountId, e);
        }

        // Delete the collection record
        collectorRecordMapper.deleteByCloudAccountId(cloudAccountId);
    }
}

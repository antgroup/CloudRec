package com.alipay.dao.mapper;

import com.alipay.dao.dto.CollectorRecordDTO;
import com.alipay.dao.po.CollectorRecordPO;

import java.util.List;

public interface CollectorRecordMapper {
    int deleteByPrimaryKey(Long id);

    int insertSelective(CollectorRecordPO row);

    CollectorRecordPO selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(CollectorRecordPO row);

    CollectorRecordPO findLastOne(String cloudAccountId);

    int findCount(CollectorRecordDTO dto);

    List<CollectorRecordPO> findList(CollectorRecordDTO dto);

    int deleteByCloudAccountId(String cloudAccountId);
}
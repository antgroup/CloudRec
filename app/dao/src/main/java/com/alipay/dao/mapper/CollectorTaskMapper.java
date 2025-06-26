package com.alipay.dao.mapper;

import com.alipay.dao.po.CollectorTaskPO;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface CollectorTaskMapper {
    int deleteByPrimaryKey(Long id);

    int insertSelective(CollectorTaskPO row);

    CollectorTaskPO selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(CollectorTaskPO row);

    List<CollectorTaskPO> findList(@Param("platform") String platform,
                                   @Param("statusList") List<String> statusList,
                                   @Param("limit") Integer limit);

    int deleteByCloudAccountId(String cloudAccountId);

    void updateStatus(@Param("idList") List<Long> idList, @Param("status") String status);

    List<CollectorTaskPO> findByIds(List<Long> idList);

    List<CollectorTaskPO> findListByCloudAccount(@Param("cloudAccountId") String cloudAccountId, @Param("taskType") String taskType, @Param("statusList") List<String> statusList);
}
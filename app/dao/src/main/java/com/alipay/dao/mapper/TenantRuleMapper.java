package com.alipay.dao.mapper;

import com.alipay.dao.dto.RuleDTO;
import com.alipay.dao.po.RulePO;
import com.alipay.dao.po.TenantRulePO;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface TenantRuleMapper {
    int deleteByPrimaryKey(Long id);

    int insert(TenantRulePO row);

    int insertSelective(TenantRulePO row);

    TenantRulePO selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(TenantRulePO row);

    int updateByPrimaryKey(TenantRulePO row);

    int findCount(RuleDTO ruleDTO);

    List<RulePO> findSortList(RuleDTO ruleDTO);

    /**
     * Find all rules without pagination for memory-based pagination
     * 
     * @param ruleDTO the rule query criteria
     * @return List of RulePO with risk statistics
     */
    List<RulePO> findAllSortList(RuleDTO ruleDTO);

    /**
     * Find risk count for specific rule and tenant
     * 
     * @param ruleId the rule ID
     * @param tenantId the tenant ID
     * @return risk count for the rule and tenant
     */
    Integer findRiskCountByRuleAndTenant(@Param("ruleId") Long ruleId, @Param("tenantId") Long tenantId);

    TenantRulePO findOne(@Param("tenantId") Long tenantId, @Param("ruleCode") String ruleCode);

    List<RulePO> findAllList(@Param("tenantId") Long tenantId);

    List<TenantRulePO> findByCode(String ruleCode);

    int deleteByRuleCode(String ruleCode);
}
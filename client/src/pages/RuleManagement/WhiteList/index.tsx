import AggregateList from '@/pages/RuleManagement/WhiteList/components/AggregateList';
import DetailList from '@/pages/RuleManagement/WhiteList/components/DetailList';
import EditDrawerForm from '@/pages/RuleManagement/WhiteList/components/EditDrawerForm';
import { queryAllRuleList } from '@/services/rule/RuleController';
import {
  ActionType,
  PageContainer,
} from '@ant-design/pro-components';
import { useIntl, useSearchParams, history } from '@umijs/max';
import { message } from 'antd';
import React, { useRef, useState, useEffect } from 'react';

const WhiteList: React.FC = () => {
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Intl API
  const intl = useIntl();
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Edit Form Visible
  const [editDrawerVisible, setEditDrawerVisible] = useState<boolean>(false);
  // White List Info
  const whiteListInfoRef = useRef<API.BaseWhiteListRuleInfo>({});
  // URL search params
  const [searchParams, setSearchParams] = useSearchParams();
  // Current selected rule code for detail view
  const [selectedRuleCode, setSelectedRuleCode] = useState<string>('');
  // Current selected rule name for breadcrumb
  const [selectedRuleName, setSelectedRuleName] = useState<string>('');
  // All rules list for mapping ruleCode to ruleName
  const [allRules, setAllRules] = useState<any[]>([]);

  /**
   * Get rule name by rule code from cached rules list
   * @param ruleCode - The rule code to look up
   * @returns The corresponding rule name or ruleCode as fallback
   */
  const getRuleNameByCode = (ruleCode: string): string => {
    const rule = allRules.find((r: any) => r.ruleCode === ruleCode);
    return rule ? rule.ruleName : ruleCode;
  };

  /**
   * Load all rules on component mount for efficient rule name mapping
   */
  useEffect(() => {
    queryAllRuleList().then((response: any) => {
      if (response?.content) {
        setAllRules(response.content);
      }
    }).catch((error) => {
      console.error('Failed to load rules list:', error);
    });
  }, []);

  /**
   * Update selected rule info when URL parameters change
   */
  useEffect(() => {
    const ruleCodeFromUrl = searchParams.get('ruleCode');
    if (ruleCodeFromUrl) {
      setSelectedRuleCode(ruleCodeFromUrl);
      // Only set rule name if allRules is loaded to ensure we get the actual ruleName
      if (allRules.length > 0) {
        const ruleName = getRuleNameByCode(ruleCodeFromUrl);
        setSelectedRuleName(ruleName);
      }
    }
  }, [searchParams, allRules]);

  // Determine view mode based on URL parameters
  const currentViewMode = searchParams.get('ruleCode') ? 'detail' : 'aggregate';



  // Edit white list
  const onClickEditWhiteList = (record: API.BaseWhiteListRuleInfo) => {
    setEditDrawerVisible(true);
    whiteListInfoRef.current = record;
  };

  // View white list (根据锁状态决定模式)
  const onClickViewWhiteList = (record: API.BaseWhiteListRuleInfo) => {
    setEditDrawerVisible(true);
    // 如果当前用户持有锁，则进入编辑模式，否则只读模式
    const isEditMode = (record as any).isLockHolder === true;
    whiteListInfoRef.current = { ...record, isEditMode } as any;
  };

  /**
   * Enter detail view for specific rule code
   * Updates URL parameters to allow sharing of direct links
   */
  const onClickEnterDetailView = (ruleCode: string, ruleName: string) => {
    // Update URL parameters for shareable links
    const newSearchParams = new URLSearchParams();
    newSearchParams.set('ruleCode', ruleCode);
    setSearchParams(newSearchParams);
  };

  /**
   * Return to aggregate view and clear URL parameters
   */
  const onClickBackToAggregate = () => {
    // Clear URL parameters to return to aggregate view
    setSearchParams({});
    
    // Reload table data when returning to aggregate view
    tableActionRef.current?.reloadAndRest?.();
  };





  return (
    <PageContainer ghost title={false} breadcrumbRender={false}>
      {contextHolder}
      {currentViewMode === 'aggregate' ? (
        <AggregateList
          tableActionRef={tableActionRef}
          onEnterDetailView={onClickEnterDetailView}
          onCreateWhiteList={() => onClickEditWhiteList({})}
        />
      ) : (
        <DetailList
          tableActionRef={tableActionRef}
          selectedRuleCode={selectedRuleCode}
          selectedRuleName={selectedRuleName}
          onBackToAggregate={onClickBackToAggregate}
          onViewWhiteList={onClickViewWhiteList}
          onCreateWhiteList={() => onClickEditWhiteList({})}
        />
      )}

      <EditDrawerForm
        editDrawerVisible={editDrawerVisible}
        setEditDrawerVisible={setEditDrawerVisible}
        whiteListDrawerInfo={whiteListInfoRef.current}
        tableActionRef={tableActionRef}
        ruleCode={selectedRuleCode}
      />
    </PageContainer>
  );
};

export default WhiteList;

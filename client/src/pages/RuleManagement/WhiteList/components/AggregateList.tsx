import styles from '@/components/Common/index.less';
import { listGroupByRuleCode, queryAllRuleList } from '@/services/rule/RuleController';
import {
  ActionType,
  ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl, useRequest } from '@umijs/max';
import { Button } from 'antd';
import React from 'react';

interface AggregateListProps {
  tableActionRef: React.MutableRefObject<ActionType | undefined>;
  onEnterDetailView: (ruleCode: string, ruleName: string) => void;
  onCreateWhiteList: () => void;
}

/**
 * Aggregate list component for white list rules grouped by rule code
 * Displays summary information and allows navigation to detail view
 */
const AggregateList: React.FC<AggregateListProps> = ({
  tableActionRef,
  onEnterDetailView,
  onCreateWhiteList,
}) => {
  const intl = useIntl();

  // Get all rule list for multi-select options
  const { data: allRuleList }: any = useRequest(
    () => {
      return queryAllRuleList({});
    },
    {
      formatResult: (r: any) =>
        r.content?.map((item: { [key: string]: any }) => ({
          ...item,
          key: item?.id,
          label: item?.ruleName,
          value: item?.ruleCode,
        })) || [],
    },
  );

  // Columns for aggregate view
  const aggregateColumns: ProColumns<any, 'text'>[] = [
    {
      title: intl.formatMessage({
        id: 'home.module.inform.columns.ruleName',
      }),
      dataIndex: 'ruleCodeList',
      valueType: 'select',
      align: 'left',
      fieldProps: {
        mode: 'multiple',
        placeholder: intl.formatMessage({
          id: 'common.select.text.placeholder',
        }),
        options: allRuleList || [],
        allowClear: true,
      },
      hideInTable: true,
    },
    {
      title: intl.formatMessage({
        id: 'home.module.inform.columns.ruleName',
      }),
      dataIndex: 'ruleCode',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record) => {
        const isGlobalConfig = record.ruleCode === 'GLOBAL_CONFIG';
        return (
          <Button
            type="link"
            style={{ padding: 0, fontWeight: isGlobalConfig ? 'bold' : 'normal' }}
            onClick={() => onEnterDetailView(record.ruleCode, record.ruleName)}
          >
            {isGlobalConfig && <span style={{ marginRight: 4 }}>📌</span>}
            {isGlobalConfig 
              ? intl.formatMessage({ id: 'rule.text.global.config.whitelist' })
              : record.ruleName
            }
          </Button>
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'common.text.count',
      }),
      dataIndex: 'count',
      valueType: 'text',
      align: 'center',
      hideInSearch: true,
    }
  ];

  return (
    <ProTable<any>
      headerTitle={
        <div className={styles['customTitle']}>
          {intl.formatMessage({
            id: 'rule.module.text.whiteList.inquiry',
          })}
        </div>
      }
      scroll={{ x: 'max-content' }}
      actionRef={tableActionRef}
      search={{
        span: 12,
        defaultCollapsed: false, // Default Expand
        collapseRender: false, // Hide expand/close button
        labelWidth: 0,
      }}
      rowKey="id"
      request={async (params) => {
        const { pageSize, current, ruleCodeList, ...reset } = params;
        
        // Aggregate view: call listGroupByRuleCode
        const postBody = {
          ...reset,
          ruleCodeList: ruleCodeList, // Pass ruleCodeList for multi-select filtering
          page: current!,
          size: pageSize!,
        };
        try {
          const { content, code } = await listGroupByRuleCode(postBody);
          
          // Handle different response formats
          let dataArray: any[] = [];
          let total = 0;
          
          if (Array.isArray(content)) {
            // If content is directly an array
            dataArray = content;
            total = content.length;
          } else if (content && typeof content === 'object') {
            // If content is an object with data property
            dataArray = Array.isArray(content.data) ? content.data : [];
            total = content.total || dataArray.length;
          }
          
          // Sort data: global whitelist first, then others
          const sortedData = dataArray.sort((a: any, b: any) => {
            if (a.ruleCode === 'GLOBAL') return -1;
            if (b.ruleCode === 'GLOBAL') return 1;
            return 0;
          });
          
          return {
            data: sortedData,
            total: total,
            success: code === 200 || false,
          };
        } catch (error) {
          console.error('Error fetching aggregate data:', error);
          return {
            data: [],
            total: 0,
            success: false,
          };
        }
      }}
      toolBarRender={() => [
        <Button
          key="create"
          type="primary"
          onClick={onCreateWhiteList}
        >
          {intl.formatMessage({
            id: 'rule.module.text.createWhiteList',
          })}
        </Button>,
      ]}
      columns={aggregateColumns}
      pagination={{
        showQuickJumper: false,
        showSizeChanger: true,
        defaultPageSize: 10,
        defaultCurrent: 1,
      }}
    />
  );
};

export default AggregateList;
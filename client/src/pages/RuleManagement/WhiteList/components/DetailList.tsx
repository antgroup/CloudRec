import styles from '@/components/Common/index.less';
import Disposition from '@/components/Disposition';
import { WhiteListRuleTypeList } from '@/pages/RuleManagement/WhiteList/const';
import {
  queryChangeWhiteListRuleStatus,
  queryDeleteWhiteListRuleById,
  queryWhiteRuleGrabLock,
  queryWhiteRuleList,
} from '@/services/rule/RuleController';
import { valueListAsValueEnum } from '@/utils/shared';
import {
  ActionType,
  ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Button, Divider, message, Popconfirm, Switch, Tooltip } from 'antd';
import dayjs from 'dayjs';
import React from 'react';

interface DetailListProps {
  tableActionRef: React.MutableRefObject<ActionType | undefined>;
  selectedRuleCode: string;
  selectedRuleName: string;
  onBackToAggregate: () => void;
  onViewWhiteList: (record: API.BaseWhiteListRuleInfo) => void;
  onCreateWhiteList: () => void;
}

/**
 * Detail list component for white list rules
 * Displays detailed information for rules under a specific rule code
 */
const DetailList: React.FC<DetailListProps> = ({
  tableActionRef,
  selectedRuleCode,
  selectedRuleName,
  onBackToAggregate,
  onViewWhiteList,
  onCreateWhiteList,
}) => {
  const intl = useIntl();
  
  // Debug logs
  console.log('DetailList props - selectedRuleCode:', selectedRuleCode);
  console.log('DetailList props - selectedRuleName:', selectedRuleName);
  const [messageApi, contextHolder] = message.useMessage();

  // Grab Lock
  const onClickObtainLock = async (record: API.BaseWhiteListRuleInfo) => {
    const postBody = { id: record.id };
    const r = await queryWhiteRuleGrabLock(postBody);
    if (r.code === 200) {
      messageApi.success(
        intl.formatMessage({
          id: 'common.message.text.edit.success',
        }),
      );
      // @ts-ignore
      tableActionRef.current?.reloadAndRest();
    }
  };

  // Update white rule status
  const onClickChangeStatus = async (record: API.BaseWhiteListRuleInfo) => {
    // Check lock status
    if (!(record as any).isLockHolder) {
      messageApi.warning(
        intl.formatMessage({ id: 'rule.message.not.holding.lock' }) 
      );
      return;
    }
    
    const postBody = {
      id: record?.id,
      enable: record?.enable === 1 ? 0 : 1,
    };
    const res: API.Result_T_ = await queryChangeWhiteListRuleStatus(
      postBody as any,
    );
    if (res.code === 200) {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.edit.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  // Delete white list
  const onClickDeleteWhiteList = async (record: API.BaseWhiteListRuleInfo) => {
    if (!(record as any).isLockHolder) {
      messageApi.warning(
        intl.formatMessage({ id: 'rule.message.not.holding.lock' })
      );
      return;
    }
    
    const postBody = {
      id: record?.id,
    };
    const r = await queryDeleteWhiteListRuleById(postBody);
    if (r.code === 200) {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.delete.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  // Columns for detail view
  const detailColumns: ProColumns<API.BaseWhiteListRuleInfo, 'text'>[] = [
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.createAndUpdateTime',
      }),
      dataIndex: 'gmtCreated',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record) => {
        return (
          <div>
            <section>{record?.gmtCreate || '-'}</section>
            <section>{record?.gmtModified || '-'}</section>
          </div>
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'tenant.module.text.tenant.name',
      }),
      dataIndex: 'tenantName',
      valueType: 'text',
      align: 'left',
      copyable: false,
    },
    {
      title: intl.formatMessage({
        id: 'rule.extend.text.whiteList.title',
      }),
      dataIndex: 'ruleName',
      valueType: 'text',
      align: 'left',
      copyable: true,
    },
    {
      title: intl.formatMessage({
        id: 'rule.extend.text.whiteList.describe',
      }),
      dataIndex: 'ruleDesc',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record) => (
        <Disposition
          text={record?.ruleDesc || '-'}
          maxWidth={240}
          rows={1}
          style={{
            color: 'rgb(51, 51, 51)',
          }}
          placement={'topLeft'}
        />
      ),
    },
    {
      title: intl.formatMessage({
        id: 'rule.table.columns.text.type',
      }),
      dataIndex: 'ruleType',
      valueType: 'select',
      valueEnum: valueListAsValueEnum(WhiteListRuleTypeList),
      align: 'center',
    },
    {
      title: intl.formatMessage({
        id: 'rule.table.columns.text.creator',
      }),
      dataIndex: 'creatorName',
      valueType: 'text',
      align: 'center',
      copyable: true,
    },
    {
      title: intl.formatMessage({
        id: 'rule.table.columns.text.config',
      }),
      dataIndex: 'search',
      valueType: 'text',
      align: 'center',
      hideInTable: true
    },

    {
      title: intl.formatMessage({
        id: 'rule.table.columns.text.lockor',
      }),
      dataIndex: 'lockHolderName',
      valueType: 'text',
      align: 'center',
      hideInSearch: true,
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.cloud.operate',
      }),
      dataIndex: 'option',
      valueType: 'option',
      align: 'center',
      fixed: 'right',
      render: (_, record: API.BaseWhiteListRuleInfo) => (
        <>
          <Button
            size={'small'}
            type={'link'}
            onClick={(): void => onViewWhiteList(record)}
          >
            {intl.formatMessage({
              id: 'common.button.text.view',
            })}
          </Button>
          <Divider type={'vertical'} style={{ margin: '0 8px 0 0' }} />
          <Tooltip
            title={!(record as any).isLockHolder ? 'please grab the lock first' : ''}
            placement="top"
          >
            <Switch
              disabled={!record?.isLockHolder}
              checkedChildren={intl.formatMessage({
                id: 'common.button.text.enable',
              })}
              unCheckedChildren={intl.formatMessage({
                id: 'common.button.text.disable',
              })}
              checked={record?.enable === 1}
              onClick={() => onClickChangeStatus(record)}
            />
          </Tooltip>
          <Divider type="vertical" style={{ margin: '0 0 0 8px' }} />

          <Divider type={'vertical'} />
          <Tooltip
            title={!(record as any).isLockHolder ? 'please grab the lock first' : ''}
            placement="top"
          >
            <Popconfirm
              title={intl.formatMessage({
                id: 'common.button.text.delete.confirm',
              })}
              onConfirm={() => onClickDeleteWhiteList(record)}
              okText={intl.formatMessage({
                id: 'common.button.text.ok',
              })}
              cancelText={intl.formatMessage({
                id: 'common.button.text.cancel',
              })}
            >
              <Button
                type="link"
                danger
                size={'small'}
                disabled={!record?.isLockHolder}
              >
                {intl.formatMessage({
                  id: 'common.button.text.delete',
                })}
              </Button>
            </Popconfirm>
          </Tooltip>
        </>
      ),
    },
  ];

  return (
    <>
      {contextHolder}
      <div style={{ marginBottom: '16px' }}>
        <Button 
          type="link" 
          onClick={onBackToAggregate}
          style={{ padding: 0, fontSize: '14px' }}
        >
          ← {intl.formatMessage({ id: 'common.button.text.back' })}
        </Button>
      </div>
      <ProTable<API.BaseWhiteListRuleInfo>
        headerTitle={
          <div className={styles['customTitle']}>
            <span>
              {selectedRuleCode === 'GLOBAL_CONFIG' 
                ? intl.formatMessage({ id: 'rule.text.global.config.whitelist' })
                : selectedRuleName
              }
            </span>
          </div>
        }
        scroll={{ x: 'max-content' }}
        actionRef={tableActionRef}
        search={{
          span: 6,
          defaultCollapsed: false, // Default Expand
          collapseRender: false, // Hide expand/close button
          labelWidth: 0,
        }}
        rowKey="id"
        request={async (params) => {
          const { pageSize, current, ruleNameFilter, ...reset } = params;
          
          // Detail view: call queryWhiteRuleList with ruleCode filter
          const postBody = {
            ...reset,
            ruleCode: selectedRuleCode,
            ruleName: ruleNameFilter, // Map ruleNameFilter to ruleName for backend
            page: current!,
            size: pageSize!,
          } as API.BaseWhiteListRuleInfo & { ruleCode?: string; isGlobal?: boolean };
          try {
             const { content, code } = await queryWhiteRuleList(postBody);
             
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
             
             return {
               data: dataArray,
               total: total,
               success: code === 200 || false,
             };
           } catch (error) {
             console.error('Error fetching detail data:', error);
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
        columns={detailColumns}
        pagination={{
          showQuickJumper: false,
          showSizeChanger: true,
          defaultPageSize: 10,
          defaultCurrent: 1,
        }}
      />
    </>
  );
};

export default DetailList;
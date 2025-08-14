import styles from '@/components/Common/index.less';
import Disposition from '@/components/Disposition';
import EditDrawerForm from '@/pages/RuleManagement/WhiteList/components/EditDrawerForm';
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
  PageContainer,
  ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Button, Divider, message, Popconfirm, Switch, Tooltip } from 'antd';
import dayjs from 'dayjs';
import React, { useRef, useState } from 'react';

const WhiteList: React.FC = () => {
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Intl API
  const intl = useIntl();
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Edit Form Visible
  const [editDrawerVisible, setEditDrawerVisible] = useState<boolean>(false);
  // White List InWfo
  const whiteListInfoRef = useRef<API.BaseWhiteListRuleInfo>({});

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

  // Update white rule status
  const onClickChangeStatus = async (record: API.BaseWhiteListRuleInfo) => {
    // 检查锁状态
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

  const columns: ProColumns<API.BaseWhiteListRuleInfo, 'text'>[] = [
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.createAndUpdateTime',
      }),
      dataIndex: 'gmtCreated',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record: API.UserInfo) => {
        return (
          <div>
            <section style={{ color: '#999' }}>
              {dayjs(record?.gmtCreate).format('YYYY-MM-DD 18:00:00') || '-'}
            </section>
            <section style={{ color: '#999' }}>
              {dayjs(record?.gmtModified).format('YYYY-MM-DD 18:00:00') || '-'}
            </section>
          </div>
        );
      },
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
      hideInTable:true
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
            onClick={(): void => onClickViewWhiteList(record)}
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
    <PageContainer ghost title={false} breadcrumbRender={false}>
      {contextHolder}
      <ProTable<API.BaseWhiteListRuleInfo>
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
          span: 6,
          defaultCollapsed: false, // Default Expand
          collapseRender: false, // Hide expand/close button
          labelWidth: 0,
        }}
        rowKey="id"
        request={async (params) => {
          const { pageSize, current, ...reset } = params;
          const postBody: API.BaseWhiteListRuleInfo = {
            ...reset,
            page: current!,
            size: pageSize!,
          };
          const { content, code } = await queryWhiteRuleList(postBody);
          return {
            data: content?.data || [],
            total: content?.total || 0,
            success: code === 200 || false,
          };
        }}
        toolBarRender={() => [
          <Button
            key="create"
            type="primary"
            onClick={() => onClickEditWhiteList({})}
          >
            {intl.formatMessage({
              id: 'rule.module.text.createWhiteList',
            })}
          </Button>,
        ]}
        columns={columns}
        pagination={{
          showQuickJumper: false,
          showSizeChanger: true,
          defaultPageSize: 10,
          defaultCurrent: 1,
        }}
      />

      <EditDrawerForm
        editDrawerVisible={editDrawerVisible}
        setEditDrawerVisible={setEditDrawerVisible}
        whiteListDrawerInfo={whiteListInfoRef.current}
        tableActionRef={tableActionRef}
      />
    </PageContainer>
  );
};

export default WhiteList;

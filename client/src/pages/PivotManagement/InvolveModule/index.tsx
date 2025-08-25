import styles from '@/components/Common/index.less';
import Disposition from '@/components/Disposition';
import PermissionWrapper from '@/components/Common/PermissionWrapper';
import EditDrawerForm from '@/pages/PivotManagement/InvolveModule/components/EditDrawerForm';
import {
  deleteInvolve,
  queryChangeStatus,
  querySubscriptionList,
} from '@/services/Involve/involveController';
import {
  ActionType,
  PageContainer,
  ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Button, Divider, Popconfirm, Switch, message } from 'antd';
import { MessageType } from 'antd/es/message/interface';
import React, { useRef, useState } from 'react';

// Subscription configuration
const InvolveContent: React.FC = () => {
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Subscription information
  const involveDrawerInfo = useRef({});
  // Intl API
  const intl = useIntl();
  // Edit Drawer Visible
  const [involveDrawerVisible, setInvolveDrawerVisible] =
    useState<boolean>(false);
  // Edit subscription status [disabled, non disabled]
  const onClickChangeStatus = async (
    record: API.InvolveInfo,
  ): Promise<void> => {
    const postBody = {
      id: record?.id,
      status: record?.status === 'valid' ? 'invalid' : 'valid',
    };
    const res: API.Result_T_ = await queryChangeStatus(postBody as any);
    if (res.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.edit.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  // New | Edit Current Subscription Configuration
  const onClickEditInvolve = (
    record: API.InvolveInfo,
    type: string = 'create',
  ): void => {
    if (type === 'edit') {
      involveDrawerInfo.current = { ...record };
      setInvolveDrawerVisible(true);
    } else {
      involveDrawerInfo.current = {};
      setInvolveDrawerVisible(true);
    }
  };

  // Delete the current subscription configuration
  const onClickRemoveInvolve = async (id: number): Promise<void> => {
    const hide: MessageType = messageApi.loading(
      intl.formatMessage({ id: 'common.message.text.delete.loading' }),
    );
    const result: API.Result_String_ = await deleteInvolve({ id });
    hide();
    if (result.code === 200 || result.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.delete.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  // Table Columns
  const columns: ProColumns<API.InvolveInfo, 'text'>[] = [
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
            <section style={{ color: '#999' }}>
              {record?.gmtCreate || '-'}
            </section>
            <section style={{ color: '#999' }}>
              {record?.gmtModified || '-'}
            </section>
          </div>
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'involve.module.text.involve.id',
      }),
      dataIndex: 'id',
      valueType: 'text',
      align: 'center',
      width: 120,
    },
    {
      title: intl.formatMessage({
        id: 'involve.module.text.involve.title',
      }),
      dataIndex: 'name',
      valueType: 'text',
      align: 'center',
      width: 240,
    },
    {
      title: intl.formatMessage({
        id: 'involve.module.text.involve.type',
      }),
      dataIndex: 'actionType',
      valueType: 'text',
      align: 'center',
      width: 320,
      hideInSearch: true,
      render: (_, record: API.InvolveInfo) => {
        return (
          <Disposition
            placement={'top'}
            text={record.actionType}
            maxWidth={320}
          />
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'rule.input.text.rule.group.creator',
      }),
      dataIndex: 'username',
      valueType: 'text',
      align: 'center',
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.cloud.operate',
      }),
      dataIndex: 'option',
      valueType: 'option',
      align: 'center',
      width: 240,
      fixed: 'right',
      render: (_, record: API.InvolveInfo) => (
        <>
          <Switch
            checkedChildren={intl.formatMessage({
              id: 'common.button.text.enable',
            })}
            unCheckedChildren={intl.formatMessage({
              id: 'common.button.text.disable',
            })}
            checked={record?.status === 'valid'}
            onClick={() => onClickChangeStatus(record)}
          />
          <Divider type="vertical" />
          <Button
            size={'small'}
            onClick={() => onClickEditInvolve(record, 'edit')}
            type="link"
          >
            {intl.formatMessage({
              id: 'common.button.text.edit',
            })}
          </Button>
          <Divider type="vertical" />
          <Popconfirm
            title={intl.formatMessage({
              id: 'common.button.text.delete.confirm',
            })}
            onConfirm={() => onClickRemoveInvolve(record.id!)}
            okText={intl.formatMessage({
              id: 'common.button.text.ok',
            })}
            cancelText={intl.formatMessage({
              id: 'common.button.text.cancel',
            })}
          >
            <Button type="link" danger size={'small'}>
              {intl.formatMessage({
                id: 'common.button.text.delete',
              })}
            </Button>
          </Popconfirm>
        </>
      ),
    },
  ];

  return (
    <PageContainer ghost title={false} breadcrumbRender={false}>
      {contextHolder}
      <ProTable<API.InvolveInfo>
        headerTitle={
          <div className={styles['customTitle']}>
            {intl.formatMessage({
              id: 'involve.module.text.involve.inquiry',
            })}
          </div>
        }
        scroll={{ x: 'max-content' }}
        actionRef={tableActionRef}
        rowKey="id"
        search={false}
        request={async (params) => {
          const { pageSize, current } = params;
          const postBody = {
            page: current!,
            size: pageSize!,
          };
          const { content, code, msg } = await querySubscriptionList(postBody);
          return {
            data: content?.data || [],
            total: content?.total || 0,
            success: (code === 200 && msg === 'success') || false,
          };
        }}
        toolBarRender={() => [
          <Button
            key="create"
            type="primary"
            onClick={() => onClickEditInvolve({})}
          >
            {intl.formatMessage({
              id: 'involve.extend.text.add',
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
        tableActionRef={tableActionRef}
        involveDrawerVisible={involveDrawerVisible}
        setInvolveDrawerVisible={setInvolveDrawerVisible}
        involveDrawerInfo={involveDrawerInfo.current}
      />
    </PageContainer>
  );
};

const Involve: React.FC = () => {
  return (
    <PermissionWrapper accessKey="isPlatformAdmin">
      <InvolveContent />
    </PermissionWrapper>
  );
};

export default Involve;

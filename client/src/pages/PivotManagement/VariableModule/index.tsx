import styles from '@/components/Common/index.less';
import PermissionWrapper from '@/components/Common/PermissionWrapper';
import {
  deleteGlobalVariableConfig,
  listGlobalVariableConfig,
} from '@/services/variable/GlobalVariableConfigCroller';
import {
  ActionType,
  PageContainer,
  ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Button, Divider, Layout, Popconfirm, message } from 'antd';
import { isEmpty } from 'lodash';
import React, { useRef, useState } from 'react';
import EditModalForm from './components/EditModalForm';

const VariableModuleContent: React.FC = () => {
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Global Variable Info
  const globalVariableConfigInfoRef = useRef<any>({});
  // Edit modal visible
  const [editFormVisible, setEditFormVisible] = useState<boolean>(false);
  // Message API
  const [messageApi] = message.useMessage();
  // Intl API
  const intl = useIntl();

  const onClickDeleteGlobalConfig = async (id: number): Promise<void> => {
    const result: API.Result_String_ = await deleteGlobalVariableConfig({ id });
    if (result.code === 200 || result.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.delete.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  const columns: ProColumns<API.GlobalVariableConfigInfo, 'text'>[] = [
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
        id: 'rule.module.text.variable.name',
      }),
      dataIndex: 'name',
      valueType: 'text',
      align: 'left',
      width: 240,
    },
    {
      title: intl.formatMessage({
        id: 'rule.module.text.variable.path',
      }),
      dataIndex: 'path',
      valueType: 'text',
      align: 'center',
    },
    {
      title: intl.formatMessage({
        id: 'rule.module.text.reference.rules',
      }),
      dataIndex: 'ruleNameList',
      key: 'ruleNameList',
      hideInSearch: true,
      render: (_, record) => (
        <>
          {!isEmpty(record?.ruleNameList) ? (
            <ul style={{ paddingInlineStart: 16 }}>
              {record.ruleNameList?.map((ruleName, index) => (
                <li key={index}>{ruleName}</li>
              ))}
            </ul>
          ) : (
            '-'
          )}
        </>
      ),
    },
    {
      title: intl.formatMessage({
        id: 'rule.input.text.rule.group.creator',
      }),
      dataIndex: 'username',
      valueType: 'text',
      align: 'left',
      width: 200,
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
      render: (_, record: API.GlobalVariableConfigInfo) => (
        <>
          <Button
            size={'small'}
            type={'link'}
            onClick={(): void => {
              setEditFormVisible(true);
              globalVariableConfigInfoRef.current = {
                ...record,
              };
            }}
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
            onConfirm={() => onClickDeleteGlobalConfig(record.id!)}
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
    <Layout>
      <PageContainer ghost title={false} breadcrumbRender={false}>
        <ProTable<API.GlobalVariableConfigInfo>
          headerTitle={
            <div className={styles['customTitle']}>
              {intl.formatMessage({
                id: 'variable.module.text.variable.inquiry',
              })}
            </div>
          }
          actionRef={tableActionRef}
          rowKey="id"
          search={{
            span: 6,
            defaultCollapsed: false, // Default Expand
            collapseRender: false, // Hide expand/close button
            labelWidth: 0,
          }}
          request={async (params) => {
            const { name, path, current, pageSize } = params;
            const postBody = {
              name,
              path,
              page: current!,
              size: pageSize!,
            };
            const { content, code } = await listGlobalVariableConfig(postBody);
            return {
              data: content?.data || [],
              total: content?.total || 0,
              success: code === 200 || false,
            };
          }}
          columns={columns}
          pagination={{
            showQuickJumper: false,
            showSizeChanger: true,
            defaultPageSize: 10,
            defaultCurrent: 1,
          }}
          options={false}
          toolBarRender={() => [
            <Button
              key="create"
              type="primary"
              onClick={(): void => {
                setEditFormVisible(true);
                globalVariableConfigInfoRef.current = {};
              }}
            >
              {intl.formatMessage({
                id: 'variable.extend.text.add',
              })}
            </Button>,
            <Button
              key="config"
              href={
                'https://cloudrec.yuque.com/org-wiki-cloudrec-iew3sz/hocvhx/ty6iu889dp3dgiws'
              }
              target={'_blank'}
              style={{
                border: '1px solid #457aff',
                color: '#457aff',
                padding: '4px 10px',
                backgroundColor: 'transparent',
              }}
            >
              {intl.formatMessage({
                id: 'variable.extend.text.config',
              })}
            </Button>,
          ]}
        />
      </PageContainer>

      <EditModalForm
        editFormVisible={editFormVisible}
        setEditFormVisible={setEditFormVisible}
        globalVariableConfigInfo={globalVariableConfigInfoRef.current}
        tableActionRef={tableActionRef}
      />
    </Layout>
  );
};

const VariableModule: React.FC = () => {
  return (
    <PermissionWrapper accessKey="isPlatformAdmin">
      <VariableModuleContent />
    </PermissionWrapper>
  );
};

export default VariableModule;

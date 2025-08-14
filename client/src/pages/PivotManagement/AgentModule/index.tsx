import styles from '@/components/Common/index.less';
import PermissionWrapper from '@/components/Common/PermissionWrapper';
import TokenModal from '@/pages/PivotManagement/AgentModule/components/showOnceToken';
import {
  exitAgent,
  getOnceToken,
  queryAgentList,
} from '@/services/agent/AgentController';
import { obtainMultiplePlatformIcon } from '@/utils/shared';
import {
  ActionType,
  PageContainer,
  ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Button, Popconfirm, Tooltip, message } from 'antd';
import React, { useRef, useState } from 'react';

const AgentModuleContent: React.FC = () => {
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Token Modal Visible
  const [modalVisible, setModalVisible] = useState(false);
  // Token Info
  const [tokenInfo, setTokenInfo] = useState({
    token: '',
    expireTime: '',
    username: '',
    script: '',
    tokenList: [],
  });
  // Message API
  const [messageApi] = message.useMessage();
  // Intl API
  const intl = useIntl();

  const onClickExitAgent = async (onceToken: string): Promise<void> => {
    const result: API.Result_String_ = await exitAgent({ onceToken });
    if (result.code === 200 || result.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.exit.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  const columns: ProColumns<API.AgentInfo, 'text'>[] = [
    {
      title: intl.formatMessage({
        id: 'collector.module.text.agent.name',
      }),
      dataIndex: 'agentName',
      valueType: 'text',
      align: 'center',
      width: 240,
    },
    {
      title: intl.formatMessage({
        id: 'common.table.columns.platform',
      }),
      dataIndex: 'platform',
      valueType: 'text',
      align: 'center',
      hideInSearch: true,
      width: 200,
      render: (_, record: API.AgentInfo) => {
        return obtainMultiplePlatformIcon(record.platform!);
      },
    },
    {
      title: intl.formatMessage({
        id: 'collector.module.text.registry.value',
      }),
      dataIndex: 'registryValue',
      valueType: 'text',
      align: 'left',
      width: 200,
    },
    {
      title: intl.formatMessage({
        id: 'collector.module.text.registry.time',
      }),
      dataIndex: 'registryTime',
      valueType: 'dateTime',
      hideInSearch: true,
      align: 'left',
      width: 200,
    },
    {
      title: 'Cron',
      dataIndex: 'cron',
      hideInSearch: true,
      align: 'left',
      width: 100,
    },
    {
      title: intl.formatMessage({
        id: 'collector.module.text.registry.user',
      }),
      dataIndex: 'username',
      hideInSearch: true,
      align: 'left',
      width: 120,
    },
    {
      title: intl.formatMessage({
        id: 'collector.module.text.registry.Information',
      }),
      dataIndex: 'healthStatus',
      hideInSearch: true,
      align: 'left',
      width: 220,
    },
    {
      title: intl.formatMessage({
        id: 'collector.module.text.registry.status',
      }),
      dataIndex: 'status',
      hideInSearch: true,
      align: 'left',
      width: 120,
      render: (_, record) => (
        <Tooltip
          title={
            record.status === 'valid'
              ? intl.formatMessage({
                  id: 'collector.module.text.status.health',
                })
              : record.status === 'invalid'
              ? intl.formatMessage({
                  id: 'collector.module.text.status.offline',
                })
              : intl.formatMessage({
                  id: 'collector.module.text.status.abnormal',
                })
          }
        >
          <div
            style={{
              width: '10px',
              height: '10px',
              borderRadius: '50%',
              backgroundColor:
                record.status === 'valid'
                  ? 'rgb(17, 133, 86)'
                  : record.status === 'invalid'
                  ? 'rgb(288, 43, 53)'
                  : 'rgb(253, 100, 8)',
            }}
          />
        </Tooltip>
      ),
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.cloud.operate',
      }),
      dataIndex: 'option',
      valueType: 'option',
      align: 'center',
      width: 120,
      render: (_, record: API.CloudAccountResult) => (
        <Popconfirm
          title={intl.formatMessage({
            id: 'collector.module.text.interrupt.process',
          })}
          onConfirm={() => onClickExitAgent(record.onceToken!)}
          okText={intl.formatMessage({
            id: 'common.button.text.ok',
          })}
          cancelText={intl.formatMessage({
            id: 'common.button.text.cancel',
          })}
        >
          <Button type="link" danger>
            {intl.formatMessage({
              id: 'collector.module.text.interrupt.process',
            })}
          </Button>
        </Popconfirm>
      ),
    },
  ];

  const handleGetToken = async (): Promise<void> => {
    const response = await getOnceToken();
    if (response.code === 200) {
      setTokenInfo({
        token: response.content.token,
        expireTime: response.content.expireTime,
        username: response.content.username,
        script: response.content.script,
        tokenList: response.content.tokenList,
      });
      setModalVisible(true);
    }
  };

  return (
    <PageContainer ghost title={false} breadcrumbRender={false}>
      <ProTable<API.AgentInfo>
        headerTitle={
          <div className={styles['customTitle']}>
            {intl.formatMessage({
              id: 'collector.module.text.collector.inquiry',
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
        options={false}
        request={async (params) => {
          const { agentName, registryValue, current, pageSize } = params;
          const postBody = {
            agentName,
            registryValue,
            page: current!,
            size: pageSize!,
          };
          const { content, code } = await queryAgentList(postBody);
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
        toolBarRender={() => [
          <Button key="getToken" type="primary" onClick={handleGetToken}>
            {intl.formatMessage({
              id: 'common.button.text.deploy',
            })}
          </Button>,
          <Button
            key="config"
            href={
              'https://cloudrec.yuque.com/org-wiki-cloudrec-iew3sz/hocvhx/ztfuupzril8i28tl'
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
              id: 'collector.extend.text.config',
            })}
          </Button>,
        ]}
      />

      <TokenModal
        visible={modalVisible}
        onClose={(): void => setModalVisible(false)}
        tokenInfo={tokenInfo}
      />
    </PageContainer>
  );
};

const AgentModule: React.FC = () => {
  return (
    <PermissionWrapper accessKey="isPlatformAdmin">
      <AgentModuleContent />
    </PermissionWrapper>
  );
};

export default AgentModule;

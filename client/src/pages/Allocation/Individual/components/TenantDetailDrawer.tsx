import { queryMember, removeUser, changeUserTenantRole } from '@/services/tenant/TenantController';
import { UserTypeList } from '@/utils/const';
import { showTotalIntlFunc, valueListAsValueEnum } from '@/utils/shared';
import {
  ActionType,
  DrawerForm,
  ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Button, Descriptions, Popconfirm, Select, Space, Switch, Typography, message, Tooltip } from 'antd';
import { UserDeleteOutlined, UserOutlined, CrownOutlined } from '@ant-design/icons';
import React, { Dispatch, SetStateAction, useRef, useState, useEffect } from 'react';
import AddMemberModal from './AddMemberModal'

const { Title } = Typography;

interface ITenantDetailDrawerProps {
  drawerVisible: boolean;
  setDrawerVisible: Dispatch<SetStateAction<boolean>>;
  tenantInfo: API.TenantInfo | null;
}

/**
 * Tenant detail drawer component - displays tenant information and member list
 * Shows tenant details and calls queryMember interface to fetch member data
 */
const TenantDetailDrawer: React.FC<ITenantDetailDrawerProps> = (props) => {
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // Add member modal state
  const [addFormVisible, setAddFormVisible] = useState<boolean>(false);
  // Tenant info for add member
  const addTenantInfoRef = useRef<any>({});

  // Component Props
  const { drawerVisible, setDrawerVisible, tenantInfo } = props;

  /**
   * Refresh member list when drawer opens
   */
  useEffect(() => {
    if (drawerVisible && tenantInfo?.id) {
      // Trigger table refresh when drawer opens
      tableActionRef.current?.reload?.();
    }
  }, [drawerVisible, tenantInfo?.id]);

  /**
   * Close drawer and reset state
   */
  const handleCloseDrawer = (): void => {
    setDrawerVisible(false);
  };

  /**
   * Handle drawer form finish
   */
  const handleFinish = async (): Promise<void> => {
    handleCloseDrawer();
  };

  /**
   * Handle remove user from tenant
   */
  const handleRemoveUser = async (userId: string): Promise<void> => {
    if (!tenantInfo?.id) return;
    
    const body = {
      userId,
      tenantId: tenantInfo.id,
    };
    
    try {
      const res = await removeUser(body);
      if (res.code === 200 || res.msg === 'success') {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.delete.success' })
        );
        tableActionRef.current?.reloadAndRest?.();
      }
    } catch (error) {
      messageApi.error(
        intl.formatMessage({ id: 'common.message.text.delete.failed' })
      );
    }
  };

  /**
   * Handle add member button click
   */
  const handleAddMember = (): void => {
    if (tenantInfo) {
      addTenantInfoRef.current = { ...tenantInfo };
      setAddFormVisible(true);
    }
  };

  /**
   * Handle user role change in current tenant
   */
  const handleRoleChange = async (userId: string, newRole: string): Promise<void> => {
    if (!tenantInfo?.id) return;
    
    const body = {
      userId,
      roleName: newRole,
      tenantId: tenantInfo.id,
    };
    
    try {
      const res = await changeUserTenantRole(body);
      if (res.code === 200 || res.msg === 'success') {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.edit.success' })
        );
        tableActionRef.current?.reloadAndRest?.();
      }
    } catch (error) {
      messageApi.error(
        intl.formatMessage({ id: 'common.message.text.edit.failed' })
      );
    }
  };

  // Table Columns for member list
  const columns: ProColumns<API.UserInfo, 'text'>[] = [
    {
      title: intl.formatMessage({
        id: 'user.module.title.user.name',
      }),
      dataIndex: 'username',
      valueType: 'text',
      align: 'center',
    },
    {
      title: intl.formatMessage({
        id: 'user.module.title.user.id',
      }),
      dataIndex: 'userId',
      valueType: 'text',
      align: 'center',
    },
    {
      title: intl.formatMessage({
        id: 'tenant.module.title.user.role',
      }),
      dataIndex: 'roleName',
      hideInSearch: true,
      align: 'center',
      width: 120,
      render: (_, record) => (
        <Select
          value={record.roleName}
          style={{ width: 120 }}
          onChange={(value) => handleRoleChange(record.userId!, value)}
          options={[
            { 
              label: (
                <span>
                  <UserOutlined style={{ marginRight: 8, color: '#1890ff' }} />
                  user
                </span>
              ), 
              value: 'user' 
            },
            { 
              label: (
                <span>
                  <CrownOutlined style={{ marginRight: 8, color: '#faad14' }} />
                  admin
                </span>
              ), 
              value: 'admin' 
            },
          ]}
        />
      ),
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.createTime',
      }),
      dataIndex: 'gmtCreate',
      valueType: 'dateTime',
      hideInSearch: true,
      align: 'center',
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.updateTime',
      }),
      dataIndex: 'gmtModified',
      valueType: 'dateTime',
      hideInSearch: true,
      align: 'center',
    },
    {
      title: intl.formatMessage({ id: 'common.title.operation' }),
      dataIndex: 'option',
      valueType: 'option',
      width: 120,
      render: (_, record) => [
        <Popconfirm
          key="remove"
          title={intl.formatMessage({ id: 'common.button.text.delete.confirm' })}
          onConfirm={() => handleRemoveUser(record.userId!)}
          okText={intl.formatMessage({ id: 'common.text.confirm' })}
          cancelText={intl.formatMessage({ id: 'common.text.cancel' })}
        >
          <Button type="link" danger icon={<UserDeleteOutlined />} />
        </Popconfirm>,
      ],
    },
  ];

  return (
    <>
      {contextHolder}
      <DrawerForm
        title={
          <div>
            <Title level={4} style={{ margin: 0, color: '#1890ff' }}>
              {tenantInfo?.tenantName || '-'}
            </Title>
          </div>
        }
        width={'60%'}
        drawerProps={{
          destroyOnClose: true,
          onClose: handleCloseDrawer,
          styles: {
            body: { padding: '24px' },
          },
        }}
        open={drawerVisible}
        onFinish={handleFinish}
        submitter={false}
      >
      {/* Tenant Basic Information */}
      <div style={{ marginBottom: 24 }}>
        <Title level={5} style={{ marginBottom: 16 }}>
          {intl.formatMessage({ id: 'tenant.module.text.basic.info' })}
        </Title>
        <Descriptions column={2} bordered>
          <Descriptions.Item
            label={intl.formatMessage({ id: 'tenant.module.title.tenant.name' })}
          >
            {tenantInfo?.tenantName || '-'}
          </Descriptions.Item>
          <Descriptions.Item
            label={intl.formatMessage({ id: 'tenant.module.text.member.count' })}
          >
            {tenantInfo?.memberCount || 0}
          </Descriptions.Item>
          <Descriptions.Item
            label={intl.formatMessage({ id: 'tenant.module.text.description' })}
            span={2}
          >
            {tenantInfo?.tenantDesc || '-'}
          </Descriptions.Item>
        </Descriptions>
      </div>

      {/* Member List */}
      <div>
        <Title level={5} style={{ marginBottom: 16 }}>
          {intl.formatMessage({ id: 'tenant.module.text.member.list' })}
        </Title>
        <ProTable<API.UserInfo>
          actionRef={tableActionRef}
          rowKey="id"
          search={false}
          options={false}
          toolBarRender={() => [
            <Button
              key="add"
              type="primary"
              onClick={handleAddMember}
            >
              {intl.formatMessage({ id: 'common.text.add' })}
            </Button>,
          ]}
          request={async (params) => {
            if (!tenantInfo?.id) {
              return {
                data: [],
                total: 0,
                success: false,
              };
            }
            
            const { pageSize, current } = params;
            const postBody = {
              id: tenantInfo.id,
              page: current!,
              size: pageSize!,
            };
            
            try {
              const { content, code } = await queryMember(postBody);
              return {
                data: content?.data || [],
                total: content?.total || 0,
                success: code === 200,
              };
            } catch (error) {
              return {
                data: [],
                total: 0,
                success: false,
              };
            }
          }}
          columns={columns}
          pagination={{
            showQuickJumper: false,
            showSizeChanger: true,
            defaultPageSize: 10,
            defaultCurrent: 1,
            showTotal: (total: number, range: [number, number]): string =>
              showTotalIntlFunc(total, range, intl?.locale),
          }}
        />
      </div>
      </DrawerForm>
      
      <AddMemberModal
            addFormVisible={addFormVisible}
            setAddFormVisible={setAddFormVisible}
            addTenantInfo={addTenantInfoRef.current}
            drawerTableActionRef={tableActionRef as React.RefObject<ActionType>}
          />
    </>
  );
};

export default TenantDetailDrawer;
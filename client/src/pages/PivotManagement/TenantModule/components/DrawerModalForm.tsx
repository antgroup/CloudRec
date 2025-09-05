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
import { Button, message, Popconfirm, Select } from 'antd';
import React, { Dispatch, SetStateAction, useRef, useState } from 'react';
import { Tooltip } from 'antd';
import { UserOutlined, CrownOutlined, UserDeleteOutlined } from '@ant-design/icons';
import AddMemberModal from '../../../Allocation/Individual/components/AddMemberModal';

interface IDrawerFormProps {
  drawerFormVisible: boolean;
  setDrawerFormVisible: Dispatch<SetStateAction<boolean>>;
  drawerInfo: Record<string, any>;
  tableActionRef: React.RefObject<ActionType | undefined>;
}

// Edit tenant member information
const DrawerModalForm: React.FC<IDrawerFormProps> = (props) => {
  // Table Action
  const drawerTableActionRef = useRef<ActionType>();
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // Add member modal state
  const [addFormVisible, setAddFormVisible] = useState<boolean>(false);
  // Tenant info for add member
  const addTenantInfoRef = useRef<any>({});

  // Component Props
  const {
    drawerFormVisible,
    drawerInfo,
    setDrawerFormVisible,
    tableActionRef,
  } = props;

  const initDrawer = async (): Promise<void> => {
    setDrawerFormVisible(false);
    await tableActionRef.current?.reloadAndRest?.();
  };

  const onClickFishDrawerForm = async (): Promise<void> => {
    await initDrawer();
  };

  /**
   * Handle add member button click
   */
  const handleAddMember = (): void => {
    if (drawerInfo) {
      addTenantInfoRef.current = { ...drawerInfo };
      setAddFormVisible(true);
    }
  };

  /**
   * Handle remove user from tenant
   */
  const handleRemoveUser = async (userId: string): Promise<void> => {
    if (!drawerInfo?.id) return;
    
    const body = {
      userId,
      tenantId: drawerInfo.id,
    };
    
    try {
      const res = await removeUser(body);
      if (res.code === 200 || res.msg === 'success') {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.delete.success' })
        );
        drawerTableActionRef.current?.reloadAndRest?.();
      }
    } catch (error) {
      messageApi.error(
        intl.formatMessage({ id: 'common.message.text.delete.failed' })
      );
    }
  };

  /**
   * Handle user role change in current tenant
   */
  const handleRoleChange = async (userId: string, newRole: string): Promise<void> => {
    if (!drawerInfo?.id) return;
    
    const body = {
      userId,
      roleName: newRole,
      tenantId: drawerInfo.id,
    };
    
    try {
      const res = await changeUserTenantRole(body);
      if (res.code === 200 || res.msg === 'success') {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.edit.success' })
        );
        drawerTableActionRef.current?.reloadAndRest?.();
      }
    } catch (error) {
      messageApi.error(
        intl.formatMessage({ id: 'common.message.text.edit.failed' })
      );
    }
  };



  // Table Columns
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
        title={intl.formatMessage({
          id: 'tenant.extend.member.edit',
        })}
        width={'50%'}
        drawerProps={{
          destroyOnClose: true,
          onClose: () => initDrawer(),
          styles: {
            body: { padding: '12px 0' },
          },
        }}
        open={drawerFormVisible}
        onFinish={onClickFishDrawerForm}
      >
        <ProTable<API.UserInfo>
          actionRef={drawerTableActionRef}
          rowKey="id"
          search={false}
          options={false}
          toolBarRender={() => [
            <Button
              key="add"
              type="primary"
              onClick={handleAddMember}
            >
              {intl.formatMessage({ id: 'common.button.text.add' })}
            </Button>,
          ]}
          request={async (params) => {
            const { pageSize, current } = params;
            const postBody = {
              id: drawerInfo.id,
              page: current!,
              size: pageSize!,
            };
            const { content, code } = await queryMember(postBody);
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
            showTotal: (total: number, range: [number, number]): string =>
              showTotalIntlFunc(total, range, intl?.locale),
          }}
        />
      </DrawerForm>
      
      <AddMemberModal
        addFormVisible={addFormVisible}
        setAddFormVisible={setAddFormVisible}
        addTenantInfo={addTenantInfoRef.current}
        drawerTableActionRef={drawerTableActionRef as React.RefObject<ActionType>}
      />
    </>
  );
};

export default DrawerModalForm;

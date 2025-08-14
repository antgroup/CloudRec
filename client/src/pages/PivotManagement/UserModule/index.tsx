import styles from '@/components/Common/index.less';
import PermissionWrapper from '@/components/Common/PermissionWrapper';
import EditModalForm from '@/pages/PivotManagement/UserModule/components/EditModalForm';
import {
  changeUserStatus,
  deleteUser,
  queryUserList,
} from '@/services/user/UserController';
import { UserTypeList } from '@/utils/const';
import { valueListAsValueEnum } from '@/utils/shared';
import {
  ActionType,
  PageContainer,
  ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Button, Divider, Popconfirm, Switch, Tooltip, message } from 'antd';
import { EditOutlined, DeleteOutlined, UserOutlined, CrownOutlined } from '@ant-design/icons';
import React, { useRef, useState } from 'react';

const UserModuleContent: React.FC = () => {
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // New | Edit Modal Form Visible
  const [editFormVisible, setEditFormVisible] = useState<boolean>(false);
  // User information
  const userInfoRef = useRef<any>({});
  // Edit user status
  const onClickChangeUserStatus = async (
    id: number,
    status: string,
  ): Promise<void> => {
    const postBody = {
      id,
      status,
    };
    const res = await changeUserStatus(postBody);
    if (res.code === 200 || res.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.edit.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };
  // Delete user
  const onClickDeleteUser = async (userId: string): Promise<void> => {
    const result: API.Result_String_ = await deleteUser({ userId });
    if (result.code === 200 || result.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.delete.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };
  // Table Columns
  const columns: ProColumns<API.UserInfo, 'text'>[] = [
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
        id: 'user.module.title.user.role',
      }),
      dataIndex: 'roleName',
      valueType: 'select',
      hideInSearch: true,
      align: 'center',
      valueEnum: valueListAsValueEnum(UserTypeList),
      render: (_, record: API.UserInfo) => {
        const isAdmin = record.roleName === 'admin';
        return (
          <Tooltip
            title={intl.formatMessage({
              id: isAdmin ? 'common.tag.text.admin' : 'common.tag.text.user',
            })}
          >
            {isAdmin ? (
              <CrownOutlined style={{ color: '#faad14', fontSize: '16px' }} />
            ) : (
              <UserOutlined style={{ color: '#1890ff', fontSize: '16px' }} />
            )}
          </Tooltip>
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.cloud.operate',
      }),
      dataIndex: 'option',
      valueType: 'option',
      align: 'center',
      render: (_, record: API.UserInfo) => (
        <>
          <Tooltip
            title={intl.formatMessage({
              id: 'common.button.text.edit',
            })}
          >
            <Button
              size={'small'}
              type={'link'}
              icon={<EditOutlined />}
              onClick={(): void => {
                setEditFormVisible(true);
                userInfoRef.current = {
                  ...record,
                };
              }}
            />
          </Tooltip>
          <Divider type={'vertical'} />
          <Popconfirm
            title={intl.formatMessage({
              id: 'common.button.text.delete.confirm',
            })}
            onConfirm={() => onClickDeleteUser(record.userId!)}
            okText={intl.formatMessage({
              id: 'common.button.text.ok',
            })}
            cancelText={intl.formatMessage({
              id: 'common.button.text.cancel',
            })}
          >
            <Tooltip
              title={intl.formatMessage({
                id: 'common.button.text.delete',
              })}
            >
              <Button
                type="link"
                danger
                size={'small'}
                icon={<DeleteOutlined />}
              />
            </Tooltip>
          </Popconfirm>
          <Divider type={'vertical'} style={{ margin: '0 12px 0 0' }} />
          <Tooltip
            title={intl.formatMessage({
              id: 'user.module.title.user.status',
            })}
          >
            <Switch
              checkedChildren={intl.formatMessage({
                id: 'common.button.text.normal',
              })}
              unCheckedChildren={intl.formatMessage({
                id: 'common.button.text.disable',
              })}
              checked={record?.status === 'valid'}
              onClick={() =>
                onClickChangeUserStatus(
                  record.id!,
                  record?.status === 'valid' ? 'invalid' : 'valid',
                )
              }
            />
          </Tooltip>
        </>
      ),
    },
  ];

  return (
    <PageContainer ghost title={false} breadcrumbRender={false}>
      {contextHolder}
      <ProTable<API.UserInfo>
        headerTitle={
          <div className={styles['customTitle']}>
            {intl.formatMessage({
              id: 'user.module.title.user.inquiry',
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
        toolBarRender={() => [
          <Button
            key="create"
            type="primary"
            onClick={(): void => {
              userInfoRef.current = {};
              setEditFormVisible(true);
            }}
          >
            {intl.formatMessage({
              id: 'user.extend.text.add',
            })}
          </Button>,
        ]}
        request={async (params) => {
          const { username, userId, pageSize, current } = params;
          const postBody = {
            username,
            userId,
            page: current!,
            size: pageSize!,
          };
          const { content, code } = await queryUserList(postBody);
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
      />

      <EditModalForm // Edit permissions
        editFormVisible={editFormVisible}
        setEditFormVisible={setEditFormVisible}
        userInfo={userInfoRef.current}
        tableActionRef={tableActionRef}
      />
    </PageContainer>
  );
};

const UserModule: React.FC = () => {
  return (
    <PermissionWrapper accessKey="isPlatformAdmin">
      <UserModuleContent />
    </PermissionWrapper>
  );
};

export default UserModule;

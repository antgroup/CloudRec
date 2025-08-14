import { queryMember } from '@/services/tenant/TenantController';
import { UserTypeList } from '@/utils/const';
import { showTotalIntlFunc, valueListAsValueEnum } from '@/utils/shared';
import {
  ActionType,
  DrawerForm,
  ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { message } from 'antd';
import React, { Dispatch, SetStateAction, useRef } from 'react';
import { Tooltip } from 'antd';
import { UserOutlined, CrownOutlined } from '@ant-design/icons';

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
  const [messageApi] = message.useMessage();
  // Intl API
  const intl = useIntl();



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

  ];

  return (
    <>
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


    </>
  );
};

export default DrawerModalForm;

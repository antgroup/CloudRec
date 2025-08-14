import styles from '@/components/Common/index.less';
import MaskedText from '@/components/Common/MaskedText';
import Disposition from '@/components/Disposition';
import AuthenModalForm from '@/pages/Allocation/Individual/components/AuthenModalForm';
import {
  createAccessKey,
  deleteAccessKey,
  queryAccessKeyList,
} from '@/services/user/UserController';
import { MinusOutlined, EditOutlined } from '@ant-design/icons';
import { ActionType, ProColumns, ProTable } from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Button, Flex, message, Popconfirm } from 'antd';
import React, { useRef, useState } from 'react';

// Certification Information List
const AuthenList: React.FC = () => {
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Create AccessKey Loading
  const [createAccessKeyLoading, setCreateAccessKeyLoading] =
    useState<boolean>(false);
  // ListTotal
  const [total, setTotal] = useState<number>(0);
  // ACCESS_INFO
  const accessInfoRef = useRef({});
  // EDIT_FORM_VISIBLE
  const [editFormVisible, setEditFormVisible] = useState<boolean>(false);

  // Create AccessKey
  const onClickCreateAK = async (): Promise<void> => {
    setCreateAccessKeyLoading(true);
    const r = await createAccessKey({});
    setCreateAccessKeyLoading(false);
    if (r.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.create.success' }),
      );
      // @ts-ignore
      tableActionRef.current?.reloadAndRest();
    }
  };

  // Delete AccessKey
  const onClickDeleteAK = async (record: API.BaseAccessInfo): Promise<void> => {
    const r = await deleteAccessKey({
      id: record?.id,
    });
    if (r.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.delete.success' }),
      );
      // @ts-ignore
      tableActionRef.current?.reloadAndRest();
    }
  };

  // Add a note
  const onClickAddRemark = (record: API.BaseAccessInfo) => {
    accessInfoRef.current = {
      ...record,
    };
    setEditFormVisible(true);
  };

  // table Columns
  const columns: ProColumns<API.BaseAccessInfo, 'text'>[] = [
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.createTime',
      }),
      dataIndex: 'gmtCreate',
      valueType: 'dateTime',
      align: 'left',
      render: (_, record: API.UserInfo) => {
        return (
          <section style={{ color: '#999' }}>
            {record?.gmtCreate || '-'}
          </section>
        );
      },
    },
    {
      title: 'ACCESS KEY',
      dataIndex: 'accessKey',
      valueType: 'text',
      align: 'left',
      render: (_, record) => (
        <Disposition
          text={record?.accessKey}
          copyable={true}
          placement={'topLeft'}
          rows={1}
        />
      ),
    },
    {
      title: 'SECRET KEY',
      dataIndex: 'secretKey',
      valueType: 'text',
      align: 'left',
      width: 320,
      render: (_, record) => (
        <MaskedText
          text={record?.secretKey || '-'}
          style={{ minWidth: 320 }}
          link={false}
        />
      ),
    },
    {
      title: intl.formatMessage({
        id: 'individual.table.columns.remark.information',
      }),
      dataIndex: 'remark',
      valueType: 'text',
      align: 'left',
      render: (_, record: API.BaseAccessInfo) => {
        return (
          <Flex align={'center'}>
            <Disposition
              text={record.remark}
              placement={'top'}
              maxWidth={240}
              rows={1}
            />
            <Button type={'link'} onClick={() => onClickAddRemark(record)}>
              <EditOutlined />
            </Button>
          </Flex>
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
      width: 120,
      render: (_, record: API.BaseAccessInfo) => (
        <Popconfirm
          title={intl.formatMessage({
            id: 'common.button.text.delete.confirm',
          })}
          onConfirm={() => onClickDeleteAK(record)}
          okText={intl.formatMessage({
            id: 'common.button.text.ok',
          })}
          cancelText={intl.formatMessage({
            id: 'common.button.text.cancel',
          })}
        >
          <Button type="link" danger>
            <MinusOutlined />
          </Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <>
      {contextHolder}
      <ProTable<API.BaseAccessInfo>
        headerTitle={
          <div className={styles['customTitle']}>
            {intl.formatMessage({
              id: 'individual.module.text.authentication.information',
            })}
          </div>
        }
        actionRef={tableActionRef}
        rowKey="id"
        search={false}
        options={false}
        toolBarRender={() => [
          <Button
            key="create"
            type="primary"
            onClick={onClickCreateAK}
            loading={createAccessKeyLoading}
            disabled={total! >= 3}
          >
            {intl.formatMessage({
              id: 'individual.module.text.add.authentication',
            })}
          </Button>,
        ]}
        request={async () => {
          const { content, code } = await queryAccessKeyList({});
          setTotal(content?.length || 0);
          return {
            data: content || [],
            total: content?.length || 0,
            success: code === 200 || false,
          };
        }}
        columns={columns}
        pagination={false}
      />

      <AuthenModalForm
        editFormVisible={editFormVisible}
        setEditFormVisible={setEditFormVisible}
        accessInfo={accessInfoRef.current}
        tableActionRef={tableActionRef}
      />
    </>
  );
};

export default AuthenList;

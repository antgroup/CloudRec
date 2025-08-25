import { BASE_URL } from '@/services';
import { joinUser } from '@/services/tenant/TenantController';
import {
  ActionType,
  ModalForm,
  ProFormSelect,
} from '@ant-design/pro-components';
import { request, useIntl } from '@umijs/max';
import { Empty, Form, FormInstance, Spin, message, Typography, Button } from 'antd';
import { isEmpty } from 'lodash';
import React, { Dispatch, SetStateAction, useState } from 'react';
import EditModalForm from '@/pages/PivotManagement/UserModule/components/EditModalForm';

const { Text } = Typography;

interface IEditFormProps {
  addFormVisible: boolean;
  setAddFormVisible: Dispatch<SetStateAction<boolean>>;
  addTenantInfo: Record<string, any>;
  drawerTableActionRef: React.RefObject<ActionType>;
}

// Add tenant members
const AddTenantMember: React.FC<IEditFormProps> = (props) => {
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Form Instance
  const [form] = Form.useForm<FormInstance>();
  // Intl API
  const intl = useIntl();
  // Component Props
  const {
    addFormVisible,
    addTenantInfo,
    setAddFormVisible,
    drawerTableActionRef,
  } = props;
  
  // Create user modal state
  const [createUserVisible, setCreateUserVisible] = useState<boolean>(false);
  // Empty user info for creating new user
  const [userInfo] = useState<Record<string, any>>({});

  const onClickFishEditForm = async (formData: any): Promise<void> => {
    const postBody = {
      ...formData,
      tenantId: addTenantInfo.id,
    };
    const res: API.Result_String_ = await joinUser(postBody);
    if (res.msg === 'success' || [200].includes(res.code!)) {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.add.success' }),
      );
      setAddFormVisible(false);
      drawerTableActionRef.current?.reloadAndRest?.();
    }
  };

  const initForm = (): void => {
    form.resetFields();
  };

  const onCancel = (): void => {
    setAddFormVisible(false);
    initForm();
  };

  const [fetching, setFetching] = useState(false);

  /**
   * Handle create user button click
   */
  const handleCreateUser = (): void => {
    setCreateUserVisible(true);
  };

  const requestWorkerInfoList = async (fuzzy: {
    keyWords: string;
  }): Promise<any> => {
    if (isEmpty(fuzzy.keyWords.trim())) return;
    setFetching(true);
    return request(`${BASE_URL}/api/user/queryUserList`, {
      method: 'POST',
      data: {
        username: fuzzy.keyWords,
      },
    })
      .then((result: any) => {
        return result?.content?.data || [];
      })
      .catch(() => {
        return [];
      })
      .finally((): void => {
        setFetching(false);
      });
  };

  return (
    <>
      {contextHolder}
      <ModalForm
        title={intl.formatMessage({
          id: 'tenant.extend.member.add',
        })}
        width={520}
        form={form}
        modalProps={{
          destroyOnClose: true,
          onCancel: () => onCancel(),
          styles: {
            body: {
              paddingTop: 12,
            },
          },
        }}
        layout={'horizontal'}
        open={addFormVisible}
        onFinish={onClickFishEditForm}
      >
        <ProFormSelect
          allowClear
          name="userId"
          label={intl.formatMessage({
            id: 'user.module.title.user.name',
          })}
          placeholder={intl.formatMessage({
            id: 'tenant.extend.member.select',
          })}
          rules={[
            {
              required: true,
            },
          ]}
          debounceTime={800}
          request={requestWorkerInfoList}
          fieldProps={{
            showSearch: true,
            filterOption: false,
            fieldNames: {
              label: 'username',
              value: 'userId',
            },
            suffixIcon: <></>,
            notFoundContent: fetching ? (
              <Spin size="small" />
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
            ),
          }}
        />
        
        {/* Create user prompt - positioned below username field */}
        <div style={{ marginLeft: intl.locale === 'en-US' ? '25%' : '2%', marginTop: 8, marginBottom: 16 }}>
          <Text type="secondary">
            暂无账号？
            <Button 
              type="link" 
              size="small"
              style={{ padding: 0, height: 'auto', fontSize: 'inherit' }}
              onClick={handleCreateUser}
            >
              立即创建
            </Button>
          </Text>
        </div>
      </ModalForm>
      
      {/* Create User Modal */}
      <EditModalForm
        editFormVisible={createUserVisible}
        setEditFormVisible={setCreateUserVisible}
        userInfo={userInfo}
        tableActionRef={drawerTableActionRef}
      />
    </>
  );
};

export default AddTenantMember;

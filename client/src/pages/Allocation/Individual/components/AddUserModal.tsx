import { createUser, updateUser } from '@/services/user/UserController';
import { UserTypeList } from '@/utils/const';
import {
  ActionType,
  ModalForm,
  ProFormRadio,
  ProFormSelect,
  ProFormText,
} from '@ant-design/pro-components';
import { useIntl, useModel } from '@umijs/max';
import { Form, FormInstance, message } from 'antd';
import { isEmpty } from 'lodash';
import React, { Dispatch, SetStateAction, useEffect } from 'react';

interface IEditFormProps {
  editFormVisible: boolean;
  setEditFormVisible: Dispatch<SetStateAction<boolean>>;
  userInfo: Record<string, any>;
  tableActionRef: React.RefObject<ActionType | undefined>;
}

// New | Edit User
const AddUserModal: React.FC<IEditFormProps> = (props) => {

  // Message Instance
  const [messageApi, contextHolder] = message.useMessage();
  // Form Instance
  const [form] = Form.useForm<FormInstance>();
  // Intl API
  const intl = useIntl();
  // Component Props
  const { editFormVisible, userInfo, setEditFormVisible, tableActionRef } =
    props;
  // Submit Form
  const onClickFishEditForm = async (formData: any): Promise<void> => {
    const { password, ...reset } = formData;
    const postBody = {
      ...reset,
      status: userInfo?.status || 'valid',
    };
    if (userInfo.id) postBody.id = userInfo?.id;
    if (!isEmpty(password)) postBody.password = password;
    const func = userInfo.id ? updateUser : createUser;
    const res: API.Result_String_ = await func(postBody);
    if (res.msg === 'success' || [200].includes(res.code!)) {
      if (userInfo?.id) {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.edit.success' }),
        );
      } else {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.create.success' }),
        );
      }
      setEditFormVisible(false);
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  useEffect((): void => {
    if (editFormVisible && !isEmpty(userInfo)) {
      form.setFieldsValue({
        ...userInfo,
      });
    }
  }, [editFormVisible, userInfo]);

  const initForm = (): void => {
    form.resetFields();
  };

  const onCancel = (): void => {
    setEditFormVisible(false);
    initForm();
  };

  return (
    <>
      {contextHolder}
      <ModalForm
        title={
          userInfo?.id
            ? intl.formatMessage({
                id: 'user.extend.title.edit',
              })
            : intl.formatMessage({
                id: 'user.extend.title.add',
              })
        }
        width={560}
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
        labelCol={{ span: intl.locale === 'en-US' ? 6 : 4 }}
        wrapperCol={{ span: intl.locale === 'en-US' ? 18 : 20 }}
        layout={'horizontal'}
        open={editFormVisible}
        onFinish={onClickFishEditForm}
      >
        <ProFormText
          name="userId"
          label={intl.formatMessage({
            id: 'user.module.title.user.id',
          })}
          rules={[
            {
              required: true,
              message: intl.formatMessage({
                id: 'user.extend.userId.message',
              }),
              pattern: /^[a-zA-Z0-9_]{5,24}$/,
            },
          ]}
          placeholder={intl.formatMessage({
            id: 'user.extend.userId.placeholder',
          })}
          fieldProps={{
            disabled: !!userInfo?.id,
          }}
        />

        <ProFormText.Password
          name="password"
          label={intl.formatMessage({
            id: 'user.module.title.user.password',
          })}
          rules={[{ required: !userInfo?.id }]}
        />

        <ProFormText
          name="username"
          label={intl.formatMessage({
            id: 'user.module.title.user.name',
          })}
          rules={[{ required: true }]}
        />
      </ModalForm>
    </>
  );
};

export default AddUserModal;

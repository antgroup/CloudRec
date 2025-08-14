import { saveTenant } from '@/services/tenant/TenantController';
import { TenantStatusList } from '@/utils/const';
import {
  ActionType,
  ModalForm,
  ProFormSelect,
  ProFormText,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Form, FormInstance, message } from 'antd';
import React, { Dispatch, SetStateAction, useEffect } from 'react';

interface IEditFormProps {
  editFormVisible: boolean;
  setEditFormVisible: Dispatch<SetStateAction<boolean>>;
  tenantInfo: Record<string, any>;
  tableActionRef: React.RefObject<ActionType | undefined>;
}

// New | Edit Tenant
const EditModalForm: React.FC<IEditFormProps> = (props) => {
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Form Instance
  const [form] = Form.useForm<FormInstance>();
  // Intl API
  const intl = useIntl();
  // Component Props
  const { editFormVisible, tenantInfo, setEditFormVisible, tableActionRef } =
    props;

  const onClickFishEditForm = async (formData: any) => {
    const postBody = {
      ...formData,
    };
    if (tenantInfo.id) postBody.id = tenantInfo.id;
    const res: API.Result = await saveTenant(postBody);
    if (res.msg === 'success') {
      if (tenantInfo.id) {
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
    if (tenantInfo.id) {
      form.setFieldsValue({
        ...tenantInfo,
      });
    }
  }, [editFormVisible, tenantInfo]);

  const onCancel = (): void => {
    setEditFormVisible(false);
  };

  return (
    <>
      {contextHolder}
      <ModalForm
        title={
          tenantInfo.id
            ? intl.formatMessage({
                id: 'tenant.extend.title.edit',
              })
            : intl.formatMessage({
                id: 'tenant.extend.title.add',
              })
        }
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
        open={editFormVisible}
        onFinish={onClickFishEditForm}
      >
        <ProFormText
          name="tenantName"
          label={intl.formatMessage({
            id: 'tenant.module.text.tenant.name',
          })}
          rules={[{ required: true }]}
          disabled={tenantInfo.disable}
        />

        <ProFormText
          name="tenantDesc"
          label={intl.formatMessage({
            id: 'tenant.module.text.tenant.description',
          })}
          rules={[{ required: true }]}
        />

        <ProFormSelect
          label={intl.formatMessage({
            id: 'tenant.extend.text.status',
          })}
          name={'status'}
          rules={[{ required: true }]}
          options={TenantStatusList as any}
          disabled={tenantInfo.disable}
        />
      </ModalForm>
    </>
  );
};

export default EditModalForm;

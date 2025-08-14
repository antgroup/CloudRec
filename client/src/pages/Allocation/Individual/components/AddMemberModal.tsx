import { BASE_URL } from '@/services';
import { joinUser, createInviteCode } from '@/services/tenant/TenantController';
import {
  ActionType,
  ModalForm,
  ProFormSelect,
} from '@ant-design/pro-components';
import { request, useIntl } from '@umijs/max';
import { Empty, Form, FormInstance, Spin, message, Typography, Button } from 'antd';
import { isEmpty } from 'lodash';
import React, { Dispatch, SetStateAction, useState } from 'react';

const { Text } = Typography;

interface IAddMemberModalProps {
  addFormVisible: boolean;
  setAddFormVisible: Dispatch<SetStateAction<boolean>>;
  addTenantInfo: Record<string, any>;
  drawerTableActionRef: React.RefObject<ActionType>;
}

/**
 * Add member modal component for tenant detail drawer
 */
const AddMemberModal: React.FC<IAddMemberModalProps> = (props) => {
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
  


  /**
   * Handle form submission to add member to tenant
   */
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

  /**
   * Initialize form fields
   */
  const initForm = (): void => {
    form.resetFields();
  };

  /**
   * Handle modal cancel action
   */
  const onCancel = (): void => {
    setAddFormVisible(false);
    initForm();
  };

  const [fetching, setFetching] = useState(false);

  /**
   * Handle invite join button click - create invite code and generate invitation URL
   */
  const handleInviteJoin = async (): Promise<void> => {
    try {
      const res: API.Result_String_ = await createInviteCode({
        currentTenantId: addTenantInfo.id
      });
      console.log(res);
       if (res.msg === 'success' || [200].includes(res.code!)) {
         const currentUrl = window.location.origin;
         const invitationUrl = `${currentUrl}/invitation?code=${res.content}`;
         
         // Copy to clipboard with fallback
         try {
           if (navigator.clipboard && navigator.clipboard.writeText) {
             await navigator.clipboard.writeText(invitationUrl);
             messageApi.success(
               intl.formatMessage({ id: 'tenant.invite.code.created.success' }) || 
               '邀请链接已生成并复制到剪贴板'
             );
           } else {
             // Fallback for browsers that don't support clipboard API
             const textArea = document.createElement('textarea');
             textArea.value = invitationUrl;
             document.body.appendChild(textArea);
             textArea.select();
             document.execCommand('copy');
             document.body.removeChild(textArea);
             messageApi.success(
               intl.formatMessage({ id: 'tenant.invite.code.created.success' }) || 
               '邀请链接已生成并复制到剪贴板'
             );
           }
         } catch (clipboardError) {
           // Show the invitation URL in a message if copy fails
           messageApi.info(
             `邀请链接已生成：${invitationUrl}`
           );
         }
       } else {
         messageApi.error(
           intl.formatMessage({ id: 'tenant.invite.code.created.failed' }) || 
           ''
         );
       }
    } catch (error) {
      messageApi.error(
        intl.formatMessage({ id: 'tenant.invite.code.created.failed' }) || 
        '生成邀请链接失败'
      );
    }
  };

  /**
   * Request user list for selection
   */
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
        
        {/* Invite join button - positioned below username field */}
        <div style={{ marginLeft: intl.locale === 'en-US' ? '25%' : '16.67%', marginTop: 8, marginBottom: 16 }}>
          <span 
            style={{ color: '#1890ff', cursor: 'pointer' }}
            onClick={handleInviteJoin}
          >
            暂时未查询到账号？立即邀请
          </span>
        </div>
      </ModalForm>

    </>
  );
};

export default AddMemberModal;
import { DEFAULT_NAME } from '@/constants';
import { userLogin } from '@/services/user/UserController';
import { LockOutlined, UserOutlined } from '@ant-design/icons';
import {
  LoginFormPage,
  PageContainer,
  ProFormText,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Button, message } from 'antd';
import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import styles from './index.less';

const LoginPage: React.FC = () => {
  // Message Instance
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // URL search params
  const [searchParams] = useSearchParams();
  // Submit Loading
  const [submitLoading, setSubmitLoading] = useState<boolean>(false);
  // Click on user login
  const onClickToLogin = async (formData: API.UserInfo): Promise<void> => {
    const { userId, password } = formData;
    const inviteCode = searchParams.get('code');
    setSubmitLoading(true);
    const r = await userLogin({
      userId,
      password,
      inviteCode: inviteCode || undefined,
    });
    setSubmitLoading(false);
    if (r.code === 200) {
      localStorage.setItem('JSESSIONID', r.msg!);
      const timer = setTimeout((): void => {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.login.success' }),
        );
        clearTimeout(timer);
        // After successful login, jump to the homepage
        window.location.href = '/home';
      }, 500);
    }
  };

  return (
    <PageContainer
      ghost
      title={false}
      breadcrumb={undefined}
      childrenContentStyle={{ padding: 0, height: '100%' }}
      className={styles['login']}
    >
      {contextHolder}
      <LoginFormPage
        backgroundImageUrl="https://gw.alipayobjects.com/zos/rmsportal/FfdJeJRQWjEeGTpqgBKj.png"
        logo="/favicon-light.ico"
        title={DEFAULT_NAME}
        subTitle={intl.formatMessage({
          id: 'individual.module.text.platform.slogan',
        })}
        onFinish={onClickToLogin}
        submitter={{
          render: () => (
            <Button
              loading={submitLoading}
              type="primary"
              htmlType="submit"
              style={{
                height: 40,
                width: '100%',
                borderRadius: 6,
                fontSize: 16,
              }}
            >
              {intl.formatMessage({ id: 'individual.button.text.sign.in' })}
            </Button>
          ),
        }}
      >
        <ProFormText
          name="userId"
          fieldProps={{
            size: 'large',
            prefix: <UserOutlined className={'prefixIcon'} />,
          }}
          placeholder={intl.formatMessage({
            id: 'individual.module.text.account',
          })}
          rules={[
            {
              required: true,
              message: intl.formatMessage({
                id: 'individual.input.text.message.account',
              }),
            },
          ]}
        />
        <ProFormText.Password
          name="password"
          fieldProps={{
            size: 'large',
            prefix: <LockOutlined className={'prefixIcon'} />,
          }}
          placeholder={intl.formatMessage({
            id: 'individual.module.text.password',
          })}
          rules={[
            {
              required: true,
              message: intl.formatMessage({
                id: 'individual.input.text.message.password',
              }),
            },
          ]}
        />
      </LoginFormPage>
    </PageContainer>
  );
};

export default LoginPage;

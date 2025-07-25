import { DEFAULT_NAME } from '@/constants';
import { checkInviteCode } from '@/services/tenant/TenantController';
import { register, userLogin, joinTenant } from '@/services/user/UserController';
import { LockOutlined, UserOutlined, MailOutlined } from '@ant-design/icons';
import {
  LoginFormPage,
  PageContainer,
  ProFormText,
} from '@ant-design/pro-components';
import { useIntl, useSearchParams } from '@umijs/max';
import { Button, message, Result, Spin } from 'antd';
import React, { useEffect, useState } from 'react';
import styles from './index.less';

/**
 * Invitation page component for handling invite code validation and user registration
 */
const InvitationPage: React.FC = () => {
  // Message Instance
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // URL search params
  const [searchParams] = useSearchParams();
  // Loading states
  const [loading, setLoading] = useState<boolean>(true);
  const [submitLoading, setSubmitLoading] = useState<boolean>(false);
  // Invitation data
  const [invitationData, setInvitationData] = useState<any>(null);
  // Page state: 'checking' | 'invalid' | 'register' | 'auto-join'
  const [pageState, setPageState] = useState<string>('checking');

  /**
   * Check if user is already logged in by verifying token existence
   */
  const checkLoginStatus = (): boolean => {
    const token = localStorage.getItem('JSESSIONID');
    return !!token;
  };

  /**
   * Validate invite code and determine next action
   */
  const validateInviteCode = async (): Promise<void> => {
    const inviteCode = searchParams.get('code');
    
    if (!inviteCode) {
      setPageState('invalid');
      setLoading(false);
      return;
    }

    try {
      const response = await checkInviteCode({ inviteCode });
      
      if (response.code === 200 && response.content) {
        setInvitationData(response.content);
        
        // Check if user is already logged in
        if (checkLoginStatus()) {
          // Auto join tenant for logged in users
          await handleAutoJoinTenant(inviteCode);
        } else {
          // Show registration form
          setPageState('register');
        }
      } else {
        setPageState('invalid');
      }
    } catch (error) {
      console.error('Error validating invite code:', error);
      setPageState('invalid');
    } finally {
      setLoading(false);
    }
  };

  /**
   * Handle auto join tenant for logged in users
   */
  const handleAutoJoinTenant = async (inviteCode: string): Promise<void> => {
    try {
      const response = await joinTenant({ inviteCode });
      
      if (response.code === 200) {
        setPageState('auto-join');
        messageApi.success(
          intl.formatMessage({ id: 'invitation.message.join.success' })
        );
        
        // Redirect to home page after successful join
        setTimeout(() => {
          window.location.href = '/home';
        }, 1500);
      } else {
        messageApi.error(
          response.msg || 
          intl.formatMessage({ id: 'invitation.message.join.failed' })
        );
        setPageState('invalid');
      }
    } catch (error) {
      console.error('Auto join tenant error:', error);
      messageApi.error(
        intl.formatMessage({ id: 'invitation.message.join.failed' })
      );
      setPageState('invalid');
    }
  };

  /**
   * Handle user registration
   */
  const handleRegister = async (formData: any): Promise<void> => {
    const { userId, username, password, confirmPassword, email } = formData;
    const inviteCode = searchParams.get('code');
    
    // Validate password confirmation
    if (password !== confirmPassword) {
      messageApi.error(
        intl.formatMessage({ id: 'invitation.message.password.mismatch' })
      );
      return;
    }

    setSubmitLoading(true);
    
    try {
      // Call register API with invite code parameter
      const response = await register({
        userId,
        username,
        password,
        code: inviteCode,
      } as any);
      
      if (response.code === 200) {
        messageApi.success(
          intl.formatMessage({ id: 'invitation.message.register.success' })
        );
        
        // Redirect to login page after successful registration
        setTimeout(() => {
          const code = searchParams.get('code');
          const loginUrl = code ? `/login?code=${code}` : '/login';
          window.location.href = loginUrl;
        }, 1500);
      } else {
        messageApi.error(
          response.msg || 
          intl.formatMessage({ id: 'invitation.message.register.failed' })
        );
      }
    } catch (error) {
      console.error('Registration error:', error);
      messageApi.error(
        intl.formatMessage({ id: 'invitation.message.register.failed' })
      );
    } finally {
      setSubmitLoading(false);
    }
  };

  /**
   * Initialize page on component mount
   */
  useEffect(() => {
    validateInviteCode();
  }, []);

  /**
   * Render loading state
   */
  if (loading) {
    return (
      <PageContainer
        ghost
        title={false}
        breadcrumb={undefined}
        childrenContentStyle={{ padding: 0, height: '100%' }}
        className={styles['invitation']}
      >
        <div style={{ 
          display: 'flex', 
          justifyContent: 'center', 
          alignItems: 'center', 
          height: '100vh' 
        }}>
          <Spin size="large" />
        </div>
      </PageContainer>
    );
  }

  /**
   * Render invalid invite code state
   */
  if (pageState === 'invalid') {
    return (
      <PageContainer
        ghost
        title={false}
        breadcrumb={undefined}
        childrenContentStyle={{ padding: 0, height: '100%' }}
        className={styles['invitation']}
      >
        <div style={{ 
          display: 'flex', 
          justifyContent: 'center', 
          alignItems: 'center', 
          height: '100vh' 
        }}>
          <Result
            status="error"
            title={intl.formatMessage({ id: 'invitation.message.invalid' })}
            subTitle={intl.formatMessage({ id: 'invitation.message.invalid.subtitle' })}
            extra={[
              <Button type="primary" key="home" onClick={() => window.location.href = '/home'}>
                {intl.formatMessage({ id: 'invitation.button.text.return.home' })}
              </Button>,
            ]}
          />
        </div>
      </PageContainer>
    );
  }

  /**
   * Render auto-join state (user already logged in)
   */
  if (pageState === 'auto-join') {
    return (
      <PageContainer
        ghost
        title={false}
        breadcrumb={undefined}
        childrenContentStyle={{ padding: 0, height: '100%' }}
        className={styles['invitation']}
      >
        <div style={{ 
          display: 'flex', 
          justifyContent: 'center', 
          alignItems: 'center', 
          height: '100vh' 
        }}>
          <Result
            status="success"
            title={intl.formatMessage({ id: 'invitation.message.join.success' })}
            subTitle={intl.formatMessage({ id: 'invitation.message.join.success.subtitle' })}
            extra={[
              <Button type="primary" key="home" onClick={() => window.location.href = '/home'}>
                {intl.formatMessage({ id: 'invitation.button.text.return.home' })}
              </Button>,
            ]}
          />
        </div>
      </PageContainer>
    );
  }

  /**
   * Render registration form
   */
  return (
    <PageContainer
      ghost
      title={false}
      breadcrumb={undefined}
      childrenContentStyle={{ padding: 0, height: '100%' }}
      className={styles['invitation']}
    >
      {contextHolder}
      <LoginFormPage
        backgroundImageUrl="https://gw.alipayobjects.com/zos/rmsportal/FfdJeJRQWjEeGTpqgBKj.png"
        logo="/favicon-light.ico"
        title={DEFAULT_NAME}
        subTitle="CloudRec's Protecting More"
        onFinish={handleRegister}
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
              {intl.formatMessage({ id: 'individual.button.text.register' })}
            </Button>
          ),
        }}
      >
        {/* Invitation Information Display */}
        {invitationData && (
          <div style={{
            marginBottom: 24,
            padding: 16,
            background: '#f6f8fa',
            borderRadius: 8,
            border: '1px solid #e1e8ed'
          }}>
            <div style={{
              fontSize: 16,
              fontWeight: 600,
              color: '#1890ff',
              marginBottom: 12,
              textAlign: 'center'
            }}>
              🎉 {intl.formatMessage({ id: 'invitation.message.invitation.received' })}
            </div>
            <div style={{ fontSize: 14, color: '#666', textAlign: 'center' }}>
              <div>
                <span style={{ margin: '0 4px' }}>{invitationData.inviter} {intl.formatMessage({ id: 'invitation.message.invitation.received' })}</span>
                <span style={{ fontWeight: 500 }}>{invitationData.tenantName}</span>
              </div>
            </div>
          </div>
        )}
        <ProFormText
          name="username"
          fieldProps={{
            size: 'large',
            prefix: <UserOutlined className={'prefixIcon'} />,
          }}
          placeholder={intl.formatMessage({ id: 'invitation.input.text.username' })}
          rules={[
            {
              required: true,
              message: intl.formatMessage({ id: 'invitation.input.text.username' }),
            },
          ]}
        />
        <ProFormText
          name="userId"
          fieldProps={{
            size: 'large',
            prefix: <UserOutlined className={'prefixIcon'} />,
          }}
          placeholder={intl.formatMessage({ id: 'invitation.input.text.user.id' })}
          rules={[
            {
              required: true,
              message: intl.formatMessage({ id: 'invitation.input.text.user.id' }),
            },
          ]}
        />
        <ProFormText
          name="email"
          fieldProps={{
            size: 'large',
            prefix: <MailOutlined className={'prefixIcon'} />,
          }}
          placeholder={intl.formatMessage({ id: 'invitation.input.text.email' })}
          rules={[
            {
              required: true,
              message: intl.formatMessage({ id: 'invitation.input.text.email' }),
            },
            {
              type: 'email',
              message: intl.formatMessage({ id: 'invitation.input.text.email.invalid' }),
            },
          ]}
        />
        <ProFormText.Password
          name="password"
          fieldProps={{
            size: 'large',
            prefix: <LockOutlined className={'prefixIcon'} />,
          }}
          placeholder={intl.formatMessage({ id: 'invitation.input.text.password' })}
          rules={[
            {
              required: true,
              message: intl.formatMessage({ id: 'invitation.input.text.password' }),
            },
            {
              min: 6,
              message: intl.formatMessage({ id: 'invitation.input.text.password.length' }),
            },
          ]}
        />
        <ProFormText.Password
          name="confirmPassword"
          fieldProps={{
            size: 'large',
            prefix: <LockOutlined className={'prefixIcon'} />,
          }}
          placeholder={intl.formatMessage({ id: 'invitation.input.text.password.confirm' })}
          rules={[
            {
              required: true,
              message: intl.formatMessage({ id: 'invitation.input.text.password.confirm' }),
            },
          ]}
        />
        
        {/* Login Link */}
        <div style={{ 
          textAlign: 'center', 
          marginBottom: 16,
          fontSize: 14,
          color: '#666'
        }}>
          {intl.formatMessage({ id: 'invitation.message.already.have.account' })}
          <a 
            style={{ 
              color: '#1890ff',
              marginLeft: 4,
              textDecoration: 'none'
            }}
            onClick={() => {
              const code = searchParams.get('code');
              const loginUrl = code ? `/login?code=${code}` : '/login';
              window.location.href = loginUrl;
            }}
          >
            {intl.formatMessage({ id: 'invitation.message.already.have.account.login' })}
          </a>
        </div>
      </LoginFormPage>
    </PageContainer>
  );
};

export default InvitationPage;
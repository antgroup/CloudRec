import SMILE from '@/assets/images/SMILE.svg';
import AuthenList from '@/pages/Allocation/Individual/components/AuthenList';
import EditModalForm from '@/pages/Allocation/Individual/components/EditModalForm';
import TenantList from '@/pages/Allocation/Individual/components/TenantList';
import { UserTypeList } from '@/utils/const';
import { obtainTimeOfDay } from '@/utils/shared';
import { EditOutlined, UserOutlined, CrownOutlined } from '@ant-design/icons';
import { PageContainer, ProCard } from '@ant-design/pro-components';
import { useAccess, useIntl } from '@umijs/max';
import { Button, Col, ConfigProvider, Flex, Form, Row, Typography, Tooltip } from 'antd';
import React, { useState } from 'react';
import '@/components/Common/index.less';
const { Text } = Typography;

// Personal Center Page
const Individual: React.FC = () => {
  const access = useAccess();
  // Intl API
  const intl = useIntl();

  const [editFormVisible, setEditFormVisible] = useState<boolean>(false);

  const onClickToChangePassword = (): void => {
    setEditFormVisible(true);
  };

  return (
    <PageContainer title={false}>
      <ConfigProvider
        theme={{
          components: {
            Form: {
              itemMarginBottom: 12,
              labelColor: 'rgba(131, 131, 131, 1)',
              labelColonMarginInlineEnd: 20,
            },
          },
        }}
      >
        <ProCard
          title={
            <Flex>
              <img
                src={SMILE}
                alt="SMILE_ICON"
                style={{ width: 23, marginRight: 6 }}
              />
              {obtainTimeOfDay()}{access?.username ? `${access.username}` : ''}
            </Flex>
          }
          style={{ marginBottom: 16 }}
        >
          <Row>
            <Col span={24}>
              <Flex justify={'space-between'}>
                <Form.Item
                  label={intl.formatMessage({
                    id: 'individual.module.text.login.user',
                  })}
                >
                  {access?.username || '***'}
                </Form.Item>
                <Button
                  onClick={onClickToChangePassword}
                  style={{ gap: 4, padding: '4px 10px' }}
                >
                  <EditOutlined />
                  {intl.formatMessage({
                    id: 'individual.module.text.change.password',
                  })}
                </Button>
              </Flex>
            </Col>
            <Col span={8}>
              <Form.Item
                label={intl.formatMessage({
                  id: 'individual.module.text.account.id',
                })}
              >
                <Text copyable style={{ color: 'rgba(74, 74, 74, 1)' }}>
                  {access?.userId || '-'}
                </Text>
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                label={intl.formatMessage({
                  id: 'individual.module.text.current.tenant',
                })}
              >
                <Text style={{ color: 'rgba(74, 74, 74, 1)' }}>
                  {access?.tenantName || '-'}
                </Text>
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                label={intl.formatMessage({
                  id: 'user.module.title.user.role',
                })}
              >
                {access?.roleName ? (
                  <Tooltip
                    title={UserTypeList.find((item) => item.value === access?.roleName)?.label || '-'}
                  >
                    {access.roleName === 'admin' ? (
                      <CrownOutlined style={{ color: '#faad14', fontSize: '16px' }} />
                    ) : (
                      <UserOutlined style={{ color: '#1890ff', fontSize: '16px' }} />
                    )}
                  </Tooltip>
                ) : (
                  <Text style={{ color: 'rgba(74, 74, 74, 1)' }}>-</Text>
                )}
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                label={intl.formatMessage({
                  id: 'cloudAccount.extend.title.createTime',
                })}
              >
                <Text style={{ color: 'rgba(74, 74, 74, 1)' }}>
                  {access?.gmtCreate || '-'}
                </Text>
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                label={intl.formatMessage({
                  id: 'cloudAccount.extend.title.updateTime',
                })}
              >
                <Text style={{ color: 'rgba(74, 74, 74, 1)' }}>
                  {access?.gmtModified || '-'}
                </Text>
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                label={intl.formatMessage({
                  id: 'individual.module.text.last.login.time',
                })}
              >
                <Text style={{ color: 'rgba(74, 74, 74, 1)' }}>
                  {access?.lastLoginTime || '-'}
                </Text>
              </Form.Item>
            </Col>
          </Row>
        </ProCard>

        <AuthenList />
        
        <ProCard
          title={
            <div className="customTitle">
              {intl.formatMessage({
                id: 'individual.module.text.my.tenants',
              })}
            </div>
          }
          style={{ marginTop: 16 }}
        >
          <TenantList />
        </ProCard>
      </ConfigProvider>

      <EditModalForm
        editFormVisible={editFormVisible}
        setEditFormVisible={setEditFormVisible}
      />
    </PageContainer>
  );
};

export default Individual;

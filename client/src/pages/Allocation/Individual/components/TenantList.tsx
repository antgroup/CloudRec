import { queryTenantListV2 } from '@/services/tenant/TenantController';
import { useIntl } from '@umijs/max';
import { Card, Col, Row, Typography, message, Spin } from 'antd';
import React, { useEffect, useState } from 'react';
import TenantDetailDrawer from './TenantDetailDrawer';

const { Text, Title } = Typography;

/**
 * My Tenants component - displays tenant information in card format
 * Shows tenantName, tenantDesc, and memberCount for each tenant
 */
const TenantList: React.FC = () => {
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // Loading state
  const [loading, setLoading] = useState<boolean>(false);
  // Tenant list data
  const [tenantList, setTenantList] = useState<API.TenantInfo[]>([]);
  // Drawer state
  const [drawerVisible, setDrawerVisible] = useState<boolean>(false);
  // Selected tenant info
  const [selectedTenant, setSelectedTenant] = useState<API.TenantInfo | null>(null);

  /**
   * Fetch tenant list data from API
   */
  const fetchTenantList = async (): Promise<void> => {
    try {
      setLoading(true);
      const response = await queryTenantListV2();
      if (response.code === 200 && response.content) {
        setTenantList(response.content);
      } else {
        messageApi.error(
          intl.formatMessage({ id: 'common.message.text.query.failed' })
        );
      }
    } catch (error) {
      messageApi.error(
        intl.formatMessage({ id: 'common.message.text.query.failed' })
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTenantList();
  }, []);

  /**
   * Handle tenant card click to open detail drawer
   */
  const handleTenantCardClick = (tenant: API.TenantInfo): void => {
    setSelectedTenant(tenant);
    setDrawerVisible(true);
  };

  return (
    <>
      {contextHolder}
      <Spin spinning={loading}>
        <Row gutter={[16, 16]}>
          {tenantList.map((tenant) => (
            <Col xs={24} sm={12} md={8} lg={6} key={tenant.id}>
              <Card
                hoverable
                style={{
                  borderRadius: 8,
                  border: '1px solid #f0f0f0',
                  background: 'rgba(22, 119, 255, 0.04)',
                  height: '100%',
                  cursor: 'pointer',
                  transition: 'all 0.3s ease',
                  transform: 'translateY(0)',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'translateY(-2px)';
                  e.currentTarget.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.1)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.boxShadow = 'none';
                }}
                bodyStyle={{ padding: 16 }}
                onClick={() => handleTenantCardClick(tenant)}
              >
                <div style={{ marginBottom: 12 }}>
                  <Title
                    level={5}
                    style={{
                      margin: 0,
                      color: '#262626',
                      fontSize: 18,
                      fontWeight: 600,
                      lineHeight: 1.4,
                    }}
                    ellipsis={{ tooltip: tenant.tenantName }}
                  >
                    {tenant.tenantName || '-'}
                  </Title>
                </div>
                
                <div style={{ marginBottom: 14 }}>
                  <Text
                    style={{
                      color: '#666',
                      fontSize: 14,
                      lineHeight: 1.4,
                      maxHeight: 40,
                      overflow: 'hidden',
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: 'vertical',
                      display: '-webkit-box',
                    }}
                  >
                    {tenant.tenantDesc || '-'}
                  </Text>
                </div>
                
                <div style={{ borderTop: '1px solid #e8e8e8', paddingTop: 14, marginTop: 14 }}>
                  <Row gutter={[16, 8]}>
                    <Col span={12}>
                      <div style={{ marginBottom: 4 }}>
                        <Text
                          style={{ fontSize: 13, fontWeight: 500, color: '#333' }}
                        >
                          {intl.formatMessage({ id: 'tenant.module.text.member.count' })}
                        </Text>
                      </div>
                      <Text
                        style={{
                          color: '#1677FF',
                          fontSize: 13,
                          display: 'block',
                        }}
                      >
                        {tenant.memberCount || 0}
                      </Text>
                    </Col>
                    
                    <Col span={12}>
                      <div style={{ marginBottom: 4 }}>
                        <Text
                          style={{ fontSize: 13, fontWeight: 500, color: '#333' }}
                        >
                          {intl.formatMessage({ id: 'common.link.text.status' }) || 'Status'}
                        </Text>
                      </div>
                      <Text
                        style={{
                          color: tenant.status === 'valid' ? '#52c41a' : '#ff4d4f',
                          fontSize: 13,
                          display: 'block',
                        }}
                      >
                        {tenant.status || '-'}
                      </Text>
                    </Col>
                    
                    <Col span={24} style={{ marginTop: 8 }}>
                      <div style={{ marginBottom: 4 }}>
                        <Text
                          style={{ fontSize: 13, fontWeight: 500, color: '#333' }}
                        >
                          {intl.formatMessage({ id: 'cloudAccount.extend.title.createAndUpdateTime' })}
                        </Text>
                      </div>
                      <div
                        style={{
                          color: '#999',
                          fontSize: 13,
                          lineHeight: '18px',
                        }}
                      >
                        <div>{tenant.gmtCreate || '-'}</div>
                        <div>{tenant.gmtModified || '-'}</div>
                      </div>
                    </Col>
                  </Row>
                </div>
              </Card>
            </Col>
          ))}
        </Row>
        
        {!loading && tenantList.length === 0 && (
          <div
            style={{
              textAlign: 'center',
              padding: '40px 0',
              color: '#999',
            }}
          >
            <Text type="secondary">
              {intl.formatMessage({ id: 'common.message.text.no.data' })}
            </Text>
          </div>
        )}
      </Spin>
      
      {/* Tenant Detail Drawer */}
      <TenantDetailDrawer
        drawerVisible={drawerVisible}
        setDrawerVisible={setDrawerVisible}
        tenantInfo={selectedTenant}
      />
    </>
  );
};

export default TenantList;
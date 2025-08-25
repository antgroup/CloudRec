import tenant from '@/assets/images/TENANT.png';
import { changeTenant } from '@/services/tenant/TenantController';
import { CaretDownOutlined, SwapOutlined, EyeOutlined, UnorderedListOutlined, AppstoreOutlined } from '@ant-design/icons';
import { ProCard } from '@ant-design/pro-components';
import { useIntl, useModel } from '@umijs/max';
import { Button, Divider, Dropdown, List, message, Card, Typography, Space, Switch, Tooltip } from 'antd';
import React, { useState, useEffect } from 'react';
import styles from './index.less';
import TenantDetailDrawer from '@/pages/Allocation/Individual/components/TenantDetailDrawer';

const { Text } = Typography;

interface ISwitchTenant {
  tenantId?: number;
  tenantName: string;
}

const LIMIT_TENANT_COUNT = 10;

// Switch Tenant
const SwitchTenant: React.FC = () => {
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // Tenant Model
  const { tenantListAdded } = useModel('tenant');
  // Initial State for current tenant info
  const { initialState } = useModel('@@initialState');
  const { tenantId, tenantName } = initialState || {};
  // View mode state: 'simple' for list view, 'detailed' for card view
  // Default to 'detailed' view and persist user preference in localStorage
  const [viewMode, setViewMode] = useState<'simple' | 'detailed'>('detailed');
  // Tenant detail drawer state
  const [drawerVisible, setDrawerVisible] = useState<boolean>(false);
  const [selectedTenant, setSelectedTenant] = useState<API.TenantInfo | null>(null);

  /**
   * Handle switch tenant
   */
  const onClickSwitchTenant = async (id: number): Promise<void> => {
    const postBody = {
      tenantId: id,
    };
    const res: API.Result_String_ = await changeTenant(postBody);
    if (res.msg === 'success' || res.code === 200) {
      messageApi.success(
        intl.formatMessage({
          id: 'layout.routes.title.switchTenantSuccess',
        })
      );
      window.location.reload();
    }
  };

  /**
   * Handle view tenant details
   */
  const handleViewTenantDetails = (tenant: API.TenantInfo): void => {
    setSelectedTenant(tenant);
    setDrawerVisible(true);
  };

  /**
   * Initialize view mode from localStorage on component mount
   */
  useEffect(() => {
    const savedViewMode = localStorage.getItem('tenant-view-mode') as 'simple' | 'detailed';
    if (savedViewMode && (savedViewMode === 'simple' || savedViewMode === 'detailed')) {
      setViewMode(savedViewMode);
    }
  }, []);

  /**
   * Toggle view mode between simple and detailed
   * Save user preference to localStorage
   */
  const handleViewModeToggle = (checked: boolean): void => {
    const newViewMode = checked ? 'detailed' : 'simple';
    setViewMode(newViewMode);
    localStorage.setItem('tenant-view-mode', newViewMode);
  };

  /**
   * Render tenant item in simple list mode
   */
  const renderSimpleItem = (item: API.TenantInfo) => (
    <List.Item
      className={styles['tenantListItem']}
      actions={[
        <Button
          disabled={item.id === tenantId}
          className={styles['switchButton']}
          type={'link'}
          onClick={() => onClickSwitchTenant(item.id!)}
          key="switchTenant"
        >
          <SwapOutlined />
        </Button>,
      ]}
    >
      <span className={styles['tenantName']}>
        {item.tenantName}
      </span>
    </List.Item>
  );

  /**
   * Render tenant item in detailed card mode
   */
  const renderDetailedItem = (item: API.TenantInfo) => (
    <Card
      key={item.id}
      size="small"
      style={{ marginBottom: 8 }}
      bodyStyle={{ padding: '12px 16px' }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ flex: 1 }}>
          <div>
            <Text strong style={{ fontSize: 14 }}>{item.tenantName}</Text>
            {item.id === tenantId && (
              <Text type="success" style={{ marginLeft: 8, fontSize: 12 }}>
                ({intl.formatMessage({ id: 'common.text.current' })})
              </Text>
            )}
          </div>
          <div style={{ marginTop: 4 }}>
            <Text type="secondary" style={{ fontSize: 12 }}>
              {item.tenantDesc || intl.formatMessage({ id: 'common.text.no.description' })}
            </Text>
          </div>
          <div style={{ marginTop: 4 }}>
            <Text type="secondary" style={{ fontSize: 12 }}>
              {intl.formatMessage({ id: 'tenant.module.text.member.count' })}: {item.memberCount || 0}
            </Text>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginLeft: 16 }}>
          <Tooltip title={intl.formatMessage({ id: 'common.button.text.view' })}>
            <Button
              type="link"
              size="small"
              icon={<EyeOutlined />}
              onClick={() => handleViewTenantDetails(item)}
              style={{ height: 24, padding: '0 4px' }}
            />
          </Tooltip>
          <Tooltip title={intl.formatMessage({ id: 'layout.routes.title.switchTenant' })}>
            <Button
              disabled={item.id === tenantId}
              type="link"
              size="small"
              icon={<SwapOutlined />}
              onClick={() => onClickSwitchTenant(item.id!)}
              style={{ height: 24, padding: '0 4px' }}
            />
          </Tooltip>
        </div>
      </div>
    </Card>
  );

  return (
    <>
      {contextHolder}
      <Dropdown
        placement="top"
        arrow={true}
        dropdownRender={() => {
          return (
            <ProCard
              bodyStyle={{
                width: viewMode === 'detailed' ? 320 : 220,
                padding: '12px 16px 6px 16px',
              }}
              boxShadow={true}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div style={{ fontSize: 13, color: 'green' }}>
                  {intl.formatMessage({
                    id: 'layout.routes.title.joinedTenant',
                  })}
                </div>
                <Space>
                  <Tooltip title={intl.formatMessage({ id: viewMode === 'simple' ? 'common.text.detailed.view' : 'common.text.simple.view' })}>
                    <Switch
                      size="small"
                      checked={viewMode === 'detailed'}
                      onChange={handleViewModeToggle}
                      checkedChildren={<AppstoreOutlined />}
                      unCheckedChildren={<UnorderedListOutlined />}
                    />
                  </Tooltip>
                </Space>
              </div>
              <Divider style={{ margin: '6px 0' }} />
              <div style={{ maxHeight: 400, overflowY: 'auto' }}>
                {viewMode === 'simple' ? (
                  <List
                    itemLayout="horizontal"
                    dataSource={tenantListAdded}
                    renderItem={renderSimpleItem}
                  />
                ) : (
                  <div>
                    {tenantListAdded?.map(renderDetailedItem)}
                  </div>
                )}
              </div>
              {tenantListAdded?.length > LIMIT_TENANT_COUNT && (
                <div className={styles['viewMoreTip']}>
                  {intl.formatMessage({
                    id: 'individual.module.text.view.more.tenant',
                  })}
                </div>
              )}
            </ProCard>
          );
        }}
      >
        <Button className={styles['currentTenant']} type={'link'}>
          <img
            src={tenant}
            alt="TENANT_ICON"
            className={styles['tenantIcon']}
          />
          {tenantName ||
            intl.formatMessage({
              id: 'layout.routes.title.noneTenant',
            })}
          <CaretDownOutlined />
        </Button>
      </Dropdown>
      
      <TenantDetailDrawer
        drawerVisible={drawerVisible}
        setDrawerVisible={setDrawerVisible}
        tenantInfo={selectedTenant}
      />
    </>
  );
};
export default SwitchTenant;

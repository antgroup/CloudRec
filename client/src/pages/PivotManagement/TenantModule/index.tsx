import styles from '@/components/Common/index.less';
import PermissionWrapper from '@/components/Common/PermissionWrapper';
import {
  queryTenantListV2,
} from '@/services/tenant/TenantController';
import {
  PageContainer,
  ProForm,
  ProFormText,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Button, Empty, Spin, message } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import React, { useRef, useState, useEffect, useCallback } from 'react';
import DrawerModalForm from './components/DrawerModalForm';
import EditModalForm from './components/EditModalForm';
import TenantCard from './components/TenantCard';
import cardStyles from './index.less';

const TenantModuleContent: React.FC = () => {
  // Intl API
  const intl = useIntl();
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Edit tenant
  const [editFormVisible, setEditFormVisible] = useState<boolean>(false);
  // Tenant information
  const tenantInfoRef = useRef<any>({});
  const drawerInfoRef = useRef<any>({});
  // Editorial Members
  const [drawerFormVisible, setDrawerFormVisible] = useState<boolean>(false);
  // Tenant list data
  const [tenantList, setTenantList] = useState<API.TenantInfo[]>([]);
  // Loading state
  const [loading, setLoading] = useState<boolean>(false);
  
  // Pagination
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 12,
    total: 0,
  });

  /**
   * Fetch tenant list data from API using queryTenantListV2
   */
  const fetchTenantList = useCallback(async () => {
    try {
      setLoading(true);
      const { content, code } = await queryTenantListV2();
      if (code === 200) {
        setTenantList(content || []);
        setPagination(prev => ({
          ...prev,
          current: 1,
          total: content?.length || 0,
        }));
      }
    } catch (error) {
      messageApi.error(
        intl.formatMessage({ id: 'common.message.text.fetch.error' }) ||
        'Failed to fetch tenant list'
      );
    } finally {
      setLoading(false);
    }
  }, [messageApi, intl]);



  /**
   * Handle edit tenant
   */
  const handleEditTenant = (tenant: API.TenantInfo): void => {
    setEditFormVisible(true);
    tenantInfoRef.current = { ...tenant };
  };

  /**
   * Handle view members
   */
  const handleViewMembers = (tenant: API.TenantInfo): void => {
    setDrawerFormVisible(true);
    drawerInfoRef.current = { ...tenant };
  };

  /**
   * Handle create new tenant
   */
  const handleCreateTenant = (): void => {
    tenantInfoRef.current = {};
    setEditFormVisible(true);
  };

  /**
   * Refresh tenant list after operations
   */
  const refreshTenantList = async (): Promise<void> => {
    await fetchTenantList();
  };

  /**
   * Create mock ActionType ref for compatibility with existing components
   */
  const mockActionRef = {
    current: {
      reload: async (resetPageIndex?: boolean): Promise<void> => {
        if (resetPageIndex) {
          setPagination(prev => ({ ...prev, current: 1 }));
        }
        await fetchTenantList();
      },
      reloadAndRest: refreshTenantList,
      reset: () => {
        setPagination({ current: 1, pageSize: 12, total: 0 });
        setTenantList([]);
      },
      clearSelected: () => {},
      pageInfo: {
        current: pagination.current,
        pageSize: pagination.pageSize,
        total: pagination.total,
      },
    },
  };

  // Load initial data
  useEffect(() => {
    fetchTenantList();
  }, []);

  return (
    <PageContainer ghost title={false} breadcrumbRender={false}>
      {contextHolder}
      
      {/* Header with title and create button */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        marginBottom: 16 
      }}>
        <div className={styles['customTitle']}>
          {intl.formatMessage({
            id: 'tenant.module.text.tenant.inquiry',
          })}
        </div>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={handleCreateTenant}
        >
          {intl.formatMessage({
            id: 'tenant.extend.text.add',
          })}
        </Button>
      </div>



      {/* Tenant cards container */}
      <div className={cardStyles['tenantModuleWrap']}>
        <Spin spinning={loading}>
          {tenantList.length > 0 ? (
            <div className={cardStyles['tenantCardList']}>
              {tenantList.map((tenant) => (
                <TenantCard
                  key={tenant.id}
                  tenant={tenant}
                  onEdit={handleEditTenant}
                  onViewMembers={handleViewMembers}
                />
              ))}
            </div>
          ) : (
            <div className={cardStyles['emptyState']}>
              <Empty
                description={
                  intl.formatMessage({ id: 'common.message.text.no.data' }) || 'No tenant data'
                }
              />
            </div>
          )}
        </Spin>
      </div>

      <EditModalForm // New | Edit
        editFormVisible={editFormVisible}
        setEditFormVisible={setEditFormVisible}
        tenantInfo={tenantInfoRef.current}
        tableActionRef={mockActionRef as any}
      />

      <DrawerModalForm // Tenant members
        drawerFormVisible={drawerFormVisible}
        setDrawerFormVisible={setDrawerFormVisible}
        drawerInfo={drawerInfoRef.current}
        tableActionRef={mockActionRef as any}
      />
    </PageContainer>
  );
};

const TenantModule: React.FC = () => {
  return (
    <PermissionWrapper accessKey="isPlatformAdmin">
      <TenantModuleContent />
    </PermissionWrapper>
  );
};

export default TenantModule;

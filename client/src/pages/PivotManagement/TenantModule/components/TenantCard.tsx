import { useIntl } from '@umijs/max';
import { Button, Col, Divider, Flex, Row, Space, message } from 'antd';
import { CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons';
import React from 'react';
import styles from '../index.less';

interface ITenantCard {
  tenant: API.TenantInfo;
  onEdit: (tenant: API.TenantInfo) => void;
  onViewMembers: (tenant: API.TenantInfo) => void;
}

/**
 * Tenant card component for displaying tenant information in card format
 * @param props - Component props containing tenant data and callback functions
 * @returns React functional component
 */
const TenantCard: React.FC<ITenantCard> = (props) => {
  // Component Props
  const { tenant, onEdit, onViewMembers } = props;
  const {
    tenantName,
    tenantDesc,
    memberCount,
    gmtCreate,
    gmtModified,
    status,
    disable,
  } = tenant;
  
  // Intl API
  const intl = useIntl();
  // Message API
  const [messageApi, contextHolder] = message.useMessage();

  /**
   * Handle edit button click
   */
  const handleEditClick = (): void => {
    if (disable) {
      messageApi.warning(
        intl.formatMessage({
          id: 'tenant.module.message.edit.disabled',
        }) || 'This tenant cannot be edited'
      );
      return;
    }
    onEdit(tenant);
  };

  /**
   * Handle view members button click
   */
  const handleViewMembersClick = (): void => {
    if (status !== 'valid') {
      messageApi.warning(
        intl.formatMessage({
          id: 'tenant.module.message.invalid.tenant',
        }) || 'Cannot view members of invalid tenant'
      );
      return;
    }
    onViewMembers(tenant);
  };

  return (
    <>
      {contextHolder}
      <div className={styles['tenantCard']}>
        <Flex justify={'space-between'} align={'flex-start'} style={{ width: '100%' }}>
          <div className={styles['tenantNameWrap']}>
            <div className={styles['tenantName']}>
              {tenantName || '-'}
            </div>
            <div className={styles['tenantDesc']}>
              {tenantDesc || '-'}
            </div>
          </div>
        </Flex>

        <Divider className={styles['divider']} />

        <Row gutter={[16, 8]}>
          <Col span={12} className={styles['propertyWrap']}>
            <div className={styles['propertyName']}>
              {intl.formatMessage({
                id: 'tenant.module.text.member.number',
              })}
            </div>
            <Button
              type={'link'}
              disabled={status !== 'valid'}
              style={{
                padding: 0,
                height: 'auto',
                color: status === 'valid' ? '#1677FF' : '#999',
                fontSize: 13,
              }}
              onClick={handleViewMembersClick}
            >
              {memberCount || 0}
            </Button>
          </Col>

          <Col span={12} className={styles['propertyWrap']}>
            <div className={styles['propertyName']}>
              {intl.formatMessage({
                id: 'common.link.text.status',
              }) || 'Status'}
            </div>
            <div
              style={{
                color: status === 'valid' ? '#52c41a' : '#ff4d4f',
                fontSize: 13,
                display: 'flex',
                alignItems: 'center',
                gap: 4,
              }}
            >
              {status === 'valid' ? (
                <CheckCircleOutlined style={{ color: '#52c41a' }} />
              ) : (
                <CloseCircleOutlined style={{ color: '#ff4d4f' }} />
              )}
              {status}
            </div>
          </Col>

          <Col span={24} className={styles['propertyWrap']}>
            <div className={styles['propertyName']}>
              {intl.formatMessage({
                id: 'cloudAccount.extend.title.createAndUpdateTime',
              })}
            </div>
            <div
              style={{
                color: '#999',
                fontSize: 13,
                lineHeight: '18px',
              }}
            >
              <div>{gmtCreate || '-'}</div>
              <div>{gmtModified || '-'}</div>
            </div>
          </Col>
        </Row>

        <Flex style={{ width: '100%', marginTop: 16 }} justify={'center'}>
          <Button
            size={'small'}
            type={'primary'}
            disabled={disable}
            style={{
              width: 64,
              height: 30,
              borderRadius: 4,
              backgroundColor: disable ? '#f5f5f5' : '#E7F1FF',
              color: disable ? '#999' : '#1677FF',
              border: 'none',
            }}
            onClick={handleEditClick}
          >
            {intl.formatMessage({
              id: 'common.button.text.edit',
            })}
          </Button>
        </Flex>
      </div>
    </>
  );
};

export default TenantCard;
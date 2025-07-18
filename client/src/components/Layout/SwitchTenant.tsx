import tenant from '@/assets/images/TENANT.png';
import { changeTenant } from '@/services/tenant/TenantController';
import { CaretDownOutlined, SwapOutlined } from '@ant-design/icons';
import { ProCard } from '@ant-design/pro-components';
import { useIntl, useModel } from '@umijs/max';
import { Button, Divider, Dropdown, List, message } from 'antd';
import React from 'react';
import styles from './index.less';

interface ISwitchTenant {
  tenantId?: number;
  tenantName: string;
}

const LIMIT_TENANT_COUNT = 5;

// Switch Tenant
const SwitchTenant: React.FC<ISwitchTenant> = (props) => {
  // Current tenant name
  const { tenantName, tenantId } = props;
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // All tenants
  const { tenantListAdded } = useModel('tenant');

  const onClickSwitchTenant = async (tenantId: number): Promise<void> => {
    const postBody = {
      tenantId,
    };
    const res: API.Result_String_ = await changeTenant(postBody);
    if (res.msg === 'success' || res.code === 200) {
      messageApi.success(
        intl.formatMessage({
          id: 'layout.routes.title.switchTenantSuccess',
        }),
      );
      window.location.reload();
    }
  };

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
                width: 220,
                padding: '12px 16px 6px 16px',
              }}
              boxShadow={true}
            >
              <div style={{ fontSize: 13, color: 'green' }}>
                {intl.formatMessage({
                  id: 'layout.routes.title.joinedTenant',
                })}
              </div>
              <Divider style={{ margin: '6px 0' }} />
              <List
                style={{ maxHeight: 200, overflowY: 'scroll' }}
                itemLayout="horizontal"
                dataSource={tenantListAdded}
                renderItem={(item: API.TenantInfo) => (
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
                )}
              />
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
    </>
  );
};
export default SwitchTenant;

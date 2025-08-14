import { Modal, Form, Row, Col, Divider, Typography, Flex, ConfigProvider } from 'antd';
import { useIntl } from 'umi';
import styles from './index.less';
import Disposition from '@/components/Disposition';
import ConditionTag from '@/components/Common/ConditionTag';
import { IValueType } from '@/utils/const';
import { JSON_EDITOR_LIST } from '../config/platformConfig';

const { Text } = Typography;

interface AccountModalProps {
  accountInfo: any;
  visible: boolean;
  onCancel: () => void;
  tenantListAll: IValueType[];
  resourceTypeList: IValueType[];
}

const AccountModal: React.FC<AccountModalProps> = ({
  accountInfo,
  visible,
  onCancel,
  tenantListAll,
  resourceTypeList,
}) => {
  const intl = useIntl();
  const [form] = Form.useForm();

  const minHeight = JSON_EDITOR_LIST?.includes(accountInfo?.platform)
    ? 600
    : 500;

  return (
    <Modal
      title={
        <div style={{ fontSize: 16, fontWeight: 500 }}>
          {intl.formatMessage({
            id: 'cloudAccount.extend.title.accountInfo',
          })}
        </div>
      }
      open={visible}
      onCancel={onCancel}
      footer={null}
      width={800}
      style={{ minHeight }}
      destroyOnClose
    >
      <ConfigProvider
        theme={{
          components: {
            Form: {
              labelColor: 'rgba(74, 74, 74, 1)',
              colorTextHeading: 'rgba(74, 74, 74, 1)',
            },
          },
        }}
      >
        <Form form={form} layout="vertical">
          <Row>
            <Col span={12}>
              <Row style={{ height: 44 }}>
                <span className={styles['leftInfoLabel']}>
                  {intl.formatMessage({
                    id: 'cloudAccount.extend.title.accountId',
                  })}
                  &nbsp;:
                </span>
                <Disposition
                  style={{ paddingTop: 11, color: '#457aff' }}
                  text={accountInfo?.cloudAccountId || '-'}
                  rows={1}
                  maxWidth={100}
                />
              </Row>
              <Row style={{ height: 44 }}>
                <span className={styles['leftInfoLabel']}>
                  {intl.formatMessage({
                    id: 'cloudAccount.extend.title.alias',
                  })}
                  &nbsp;:
                </span>
                <Disposition
                  style={{ paddingTop: 11, color: '#457aff' }}
                  text={accountInfo?.alias || '-'}
                  rows={1}
                  maxWidth={100}
                />
              </Row>
              <Row style={{ height: 44 }}>
                <span className={styles['leftInfoLabel']}>
                  {intl.formatMessage({
                    id: 'cloudAccount.extend.title.platform',
                  })}
                  &nbsp;:
                </span>
                <Disposition
                  style={{ paddingTop: 11, color: '#457aff' }}
                  text={
                    resourceTypeList
                      ?.filter((item: IValueType): boolean =>
                        item.value === accountInfo?.platform,
                      )
                      ?.map((item: IValueType): string =>
                        intl.formatMessage({
                          id: item.label,
                        }),
                      )
                      ?.toString() || '-'
                  }
                  rows={1}
                  maxWidth={100}
                />
              </Row>
              <Row style={{ height: 44 }}>
                <span className={styles['leftInfoLabel']}>
                  {intl.formatMessage({
                    id: 'common.select.label.tenant',
                  })}
                  &nbsp;:
                </span>
                <Disposition
                  style={{ paddingTop: 11, color: '#457aff' }}
                  text={
                    tenantListAll?.find(
                      (item: IValueType): boolean =>
                        item.value === accountInfo?.tenantId,
                    )?.label || '-'
                  }
                  rows={1}
                  maxWidth={100}
                />
              </Row>
            </Col>
            <Col span={12}>
              <Row style={{ height: 44 }}>
                <span className={styles['rightInfoLabel']}>
                  {intl.formatMessage({
                    id: 'cloudAccount.extend.title.asset.number',
                  })}
                  &nbsp;:
                </span>
                <span
                  className={styles['basicInfoValue']}
                  style={{ color: '#457aff' }}
                >
                  {accountInfo?.resourceCount || 0}
                </span>
              </Row>
              <Row>
                <span
                  className={styles['rightInfoLabel']}
                  style={{ height: 44 }}
                >
                  {JSON_EDITOR_LIST?.includes(accountInfo?.platform)
                    ? `GCP KEY ${intl.formatMessage({
                        id: 'common.link.text.status',
                      })} : `
                    : `AK/SK ${intl.formatMessage({
                        id: 'common.link.text.status',
                      })} : `}
                </span>
                <Flex align={'center'}>
                  <ConditionTag state={accountInfo?.status} />
                </Flex>
              </Row>
            </Col>
          </Row>

          <Form.Item
            label={intl.formatMessage({
              id: 'cloudAccount.extend.title.lastScanTime',
            })}
          >
            <Text style={{ color: 'rgba(74, 74, 74, 1)' }}>
              {accountInfo?.lastScanTime || ' -'}
            </Text>
          </Form.Item>
          <Form.Item
            label={intl.formatMessage({
              id: 'cloudAccount.extend.title.createTime',
            })}
          >
            <Text style={{ color: 'rgba(74, 74, 74, 1)' }}>
              {accountInfo?.gmtCreate || '-'}
            </Text>
          </Form.Item>
          <Form.Item
            label={intl.formatMessage({
              id: 'cloudAccount.extend.title.updateTime',
            })}
          >
            <Text style={{ color: 'rgba(74, 74, 74, 1)' }}>
              {accountInfo?.gmtModified || '-'}
            </Text>
          </Form.Item>
        </Form>
      </ConfigProvider>
      <Divider
        style={{
          margin: '18px 0 0 0',
          borderColor: '#457aff',
          opacity: 0.25,
        }}
      />
    </Modal>
  );
};

export default AccountModal;

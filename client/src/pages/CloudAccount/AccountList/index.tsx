import AccountCard from '@/pages/CloudAccount/AccountList/components/AccountCard';
import EditModalForm from '@/pages/CloudAccount/AccountList/components/EditModalForm';
import {
  cloudAccountBaseInfoList,
  queryCloudAccountList,
} from '@/services/account/AccountController';
import { usePlatformDefaultSelection } from '@/hooks/usePlatformDefaultSelection';
import { showTotalIntlFunc, valueListAddIcon } from '@/utils/shared';
import { ProCard } from '@ant-design/pro-components';
import { FormattedMessage, useIntl, useModel, useRequest } from '@umijs/max';
import {
  Button,
  Checkbox,
  Col,
  Empty,
  Flex,
  Form,
  Pagination,
  Row,
  Select,
  Space,
  Spin,
} from 'antd';
import { debounce, isEmpty } from 'lodash';
import React, { useEffect, useMemo, useRef, useState } from 'react';
import styles from '../index.less';

const DEFAULT_PAGE_NUMBER = 1;
const DEFAULT_PAGE_SIZE = 12;

const COLLECTION_STATUS_LIST = [
  {
    label: <FormattedMessage id={'cloudAccount.module.search.open'} />,
    value: 'valid',
  },
  {
    label: <FormattedMessage id={'cloudAccount.module.search.stop'} />,
    value: 'invalid',
  },
  {
    label: <FormattedMessage id={'cloudAccount.module.search.scanning'} />,
    value: 'running',
  },
  {
    label: <FormattedMessage id={'cloudAccount.module.search.waitingToScan'} />,
    value: 'waiting',
  },
];

// Cloud Account - Cloud Account List
const AccountList: React.FC = () => {
  const { platformList } = useModel('rule');
  // Form Instance
  const [form] = Form.useForm();
  // Watch platform list changes
  const watchedPlatformList = Form.useWatch('platformList', form);
  // Intl API
  const intl = useIntl();
  // Cloud account information
  const accountInfoRef = useRef<any>({});
  // New | Edit Modal Form Visible
  const [editFormVisible, setEditFormVisible] = useState<boolean>(false);
  // CurrentPage
  const [current, setCurrent] = useState<number>(DEFAULT_PAGE_NUMBER);
  // PageSize
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE);
  // Track if initial load is completed
  const [initialLoaded, setInitialLoaded] = useState<boolean>(false);

  // Cloud account list data
  const {
    data: cloudAccountData,
    run: requestCloudAccountList,
    loading: cloudAccountListLoading,
  } = useRequest(
    (params: API.CloudAccountResult) => {
      return queryCloudAccountList(params);
    },
    {
      manual: true,
      formatResult: (r) => r.content,
    },
  );

  // Request to initialize data
  const requestInitData = async (): Promise<void> => {
    setCurrent(DEFAULT_PAGE_NUMBER);
    setPageSize(DEFAULT_PAGE_SIZE);
    form?.resetFields();
    await requestCloudAccountList({
      page: DEFAULT_PAGE_NUMBER,
      size: DEFAULT_PAGE_SIZE,
    });
  };

  // Request data based on filtering criteria
  const requestCurrentData = async (): Promise<void> => {
    setCurrent(DEFAULT_PAGE_NUMBER);
    setPageSize(DEFAULT_PAGE_SIZE);
    const formData = form.getFieldsValue();
    await requestCloudAccountList({
      ...formData,
      page: DEFAULT_PAGE_NUMBER,
      size: DEFAULT_PAGE_SIZE,
    });
  };

  // reset
  const onClickToReset = (): void => {
    form.resetFields();
  };

  // query
  const onClickToFinish = (formData: Record<string, any>): void => {
    setCurrent(DEFAULT_PAGE_NUMBER);
    setPageSize(DEFAULT_PAGE_SIZE);
    requestCloudAccountList({
      ...formData,
      page: DEFAULT_PAGE_NUMBER,
      size: DEFAULT_PAGE_SIZE,
    });
  };

  // Cloud account list data
  const {
    data: baseCloudAccountList,
    run: requestCloudAccountBaseInfoList,
    loading: fetching,
  } = useRequest(
    (params: { cloudAccountSearch?: string; platformList?: string[] }) => {
      return cloudAccountBaseInfoList({ ...params });
    },
    {
      formatResult: (r) => {
        if (r.msg === 'success') {
          return (
            r?.content?.accountAliasList?.map((item: string) => ({
              label: item,
              value: item,
            })) || []
          );
        }
      },
    },
  );

  // Use custom hook for default platform selection
  usePlatformDefaultSelection({
    platformList,
    form,
    requestCloudAccountBaseInfoList,
    platformFieldName: 'platformList'
  });

  // Initial load effect - runs once after platform hook has had a chance to set defaults
  useEffect((): (() => void) | void => {
    if (!initialLoaded) {
      // Delay initial request to allow platform hook to set defaults
      const timer = setTimeout(() => {
        const currentPlatformList = form.getFieldValue('platformList');
        if (currentPlatformList && currentPlatformList.length > 0) {
          requestCloudAccountList({
            page: current,
            size: pageSize,
            platformList: currentPlatformList,
          });
        } else {
          requestCloudAccountList({
            page: current,
            size: pageSize,
          });
        }
        setInitialLoaded(true);
      }, 100); // Small delay to ensure hook has executed
      
      return () => clearTimeout(timer);
    }
  }, [initialLoaded, current, pageSize]);

  // Handle pagination changes (not platform changes, as those are handled by onChange)
  useEffect((): void => {
    if (initialLoaded && (current !== DEFAULT_PAGE_NUMBER || pageSize !== DEFAULT_PAGE_SIZE)) {
      const currentPlatformList = form.getFieldValue('platformList');
      if (currentPlatformList && currentPlatformList.length > 0) {
        requestCloudAccountList({
          page: current,
          size: pageSize,
          platformList: currentPlatformList,
        });
      } else {
        requestCloudAccountList({
          page: current,
          size: pageSize,
        });
      }
    }
  }, [current, pageSize, initialLoaded]);

  // Cloud account list filtering
  const debounceFetcher = useMemo(() => {
    const loadOptions = (fuzzy: string): void => {
      // if (isEmpty(fuzzy)) return;
      requestCloudAccountBaseInfoList({
        platformList: form.getFieldValue('platformList') || [],
        cloudAccountSearch: fuzzy,
      });
    };
    return debounce(loadOptions, 500);
  }, [cloudAccountBaseInfoList]);

  return (
    <>
      <ProCard style={{ marginBottom: 16 }}>
        <Form form={form} onFinish={onClickToFinish}>
          <Row gutter={[24, 24]}>
            <Col span={24}>
              <Form.Item
                name="platformList"
                label={intl.formatMessage({
                  id: 'common.select.label.cloudPlatform',
                })}
                style={{ marginBottom: 16 }}
              >
                <Checkbox.Group
                  options={valueListAddIcon(platformList)}
                  onChange={(value) => {
                    const selectedPlatforms = (value as string[]) || [];
                    // Update cloud account base info list for dropdown
                    requestCloudAccountBaseInfoList({
                      platformList: selectedPlatforms,
                    });
                    // Immediately update main cloud account list when platform changes
                    requestCloudAccountList({
                      page: DEFAULT_PAGE_NUMBER,
                      size: pageSize,
                      platformList: selectedPlatforms.length > 0 ? selectedPlatforms : undefined,
                    });
                    // Reset pagination to first page
                    setCurrent(DEFAULT_PAGE_NUMBER);
                  }}
                />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={[24, 24]}>
            <Col span={6}>
              <Form.Item
                name="cloudAccountId"
                label={intl.formatMessage({
                  id: 'common.select.label.cloudAccount',
                })}
                style={{ marginBottom: 0, width: '100%' }}
              >
                <Select
                  allowClear
                  showSearch
                  placeholder={intl.formatMessage({
                    id: 'common.select.query.text.placeholder',
                  })}
                  notFoundContent={fetching && <Spin size="small" />}
                  onSearch={debounceFetcher}
                  options={baseCloudAccountList || []}
                />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item
                name="status"
                label={intl.formatMessage({
                  id: 'common.select.label.Collection.status',
                })}
                style={{ marginBottom: 0, width: '100%' }}
              >
                <Select
                  allowClear
                  placeholder={intl.formatMessage({
                    id: 'common.select.text.placeholder',
                  })}
                  options={COLLECTION_STATUS_LIST}
                />
              </Form.Item>
            </Col>
            <Col span={6} offset={6} style={{ width: '100%' }}>
              <Flex justify={'flex-end'} style={{ width: '100%' }}>
                <Form.Item style={{ marginBottom: 0 }}>
                  <Space size={8}>
                    <Button onClick={onClickToReset}>
                      {intl.formatMessage({
                        id: 'common.button.text.reset',
                      })}
                    </Button>
                    <Button
                      type={'primary'}
                      htmlType="submit"
                      loading={cloudAccountListLoading}
                    >
                      {intl.formatMessage({
                        id: 'common.button.text.query',
                      })}
                    </Button>
                  </Space>
                </Form.Item>
              </Flex>
            </Col>
          </Row>
        </Form>
      </ProCard>

      <ProCard style={{ minHeight: 488 }}>
        <Row style={{ marginBottom: 28 }} justify={'end'}>
          <Button
            key="create"
            type="primary"
            onClick={(): void => {
              setEditFormVisible(true);
              accountInfoRef.current = {};
            }}
          >
            {intl.formatMessage({
              id: 'common.button.text.add',
            })}
          </Button>
        </Row>

        <Row className={styles['cloudAccountWrap']}>
          <Spin spinning={cloudAccountListLoading}>
            {!isEmpty(cloudAccountData?.data) ? (
              <div className={styles['cloudAccountList']}>
                {cloudAccountData?.data?.map(
                  (account: API.CloudAccountResult) => (
                    <AccountCard
                      account={account}
                      key={account.id}
                      requestInitData={requestInitData}
                      requestCurrentData={requestCurrentData}
                    />
                  ),
                )}
              </div>
            ) : (
              <Flex
                align={'center'}
                justify={'center'}
                style={{ width: ' 100%', minHeight: 356 }}
              >
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
              </Flex>
            )}
          </Spin>
        </Row>

        <Row>
          <Flex justify={'center'} style={{ width: '100%', marginTop: '16px' }}>
            <Pagination
              onChange={(current: number, pageSize: number): void => {
                setCurrent(current);
                setPageSize(pageSize);
                requestCloudAccountList({
                  ...form.getFieldsValue(),
                  page: current,
                  size: pageSize,
                });
              }}
              current={current}
              pageSize={pageSize}
              size={'small'}
              showTotal={(total: number, range: [number, number]): string =>
                showTotalIntlFunc(total, range, intl?.locale)
              }
              total={cloudAccountData?.total || 0}
              showSizeChanger={true}
              pageSizeOptions={[12, 24]}
            />
          </Flex>
        </Row>
      </ProCard>

      <EditModalForm // Add | Edit Cloud Account
        editFormVisible={editFormVisible}
        setEditFormVisible={setEditFormVisible}
        accountInfo={accountInfoRef.current}
        requestCurrentData={requestCurrentData}
      />
    </>
  );
};

export default AccountList;

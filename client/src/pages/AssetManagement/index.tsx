import ExpandIcon from '@/components/Common/ExpandIcon';
import LevelTag from '@/components/Common/LevelTag';
import ThemeTag from '@/components/Common/ThemeTag';
import styleType from '@/components/Common/index.less';
import Disposition from '@/components/Disposition';
import AssetDrawer from '@/pages/AssetManagement/components/AssetDrawer';
import AssetInform from '@/pages/AssetManagement/components/AssetInform';
import { AssetSortMethodMap } from '@/pages/AssetManagement/const';
import { cloudAccountBaseInfoList } from '@/services/account/AccountController';
import {
  queryResourceList,
  queryResourceRiskQuantity,
} from '@/services/asset/AssetController';
import { queryGroupTypeList } from '@/services/resource/ResourceController';
import { RiskLevelList } from '@/utils/const';
import {
  obtainFirstProperty,
  obtainPlatformIcon,
  valueListAddIcon,
} from '@/utils/shared';
import { EditOutlined } from '@ant-design/icons';
import {
  ActionType,
  PageContainer,
  ProCard,
  ProColumns,
  ProFormInstance,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl, useLocation, useModel, useRequest } from '@umijs/max';
import {
  Button,
  Cascader,
  Checkbox,
  Col,
  ConfigProvider,
  Empty,
  Form,
  Input,
  Row,
  Select,
  Space,
  Spin,
  Typography,
} from 'antd';
import { debounce, isEmpty } from 'lodash';
import React, { useEffect, useMemo, useRef, useState } from 'react';
import styles from './index.less';
const { Paragraph } = Typography;

const COMMON_STYLES = {
  formItem: {
    marginBottom: 0,
    color: '#999',
    fontSize: '12px',
  },
  paragraph: {
    marginBottom: 0,
    fontSize: '12px',
    color: '#999',
  },
  paragraphTable: {
    maxWidth: '300px',
  },
  paragraphExpanded: {
    maxWidth: '500px',
  },
};

interface IRiskQuantity {
  record: API.BaseAssetResultInfo;
}

const RiskQuantity: React.FC<IRiskQuantity> = (props) => {
  // Component Props
  const { record } = props;
  // Intl API
  const intl = useIntl();

  // According to the cloud platform, obtain a list of resource types
  const { data: resourceRiskQuantity, run: requestResourceRiskQuantity } =
    useRequest(
      (id: number) => {
        return queryResourceRiskQuantity({ idList: [id] });
      },
      {
        manual: true,
        formatResult: (r: API.Result_AssetRiskQuantity) => r.content[0],
      },
    );

  useEffect((): void => {
    if (record?.id) requestResourceRiskQuantity(Number(record.id!));
  }, [record]);

  return (
    <Space size={2}>
      <Button
        type={'link'}
        style={{ padding: 0 }}
        size={'small'}
        target={'_blank'}
        href={`/riskManagement/riskList?platform=${record?.platform}&riskLevel=${RiskLevelList[0].value}&resourceId=${record?.resourceId}`}
        rel={'prefetch'}
      >
        <LevelTag
          level={'HIGH'}
          text={`${intl.formatMessage({
            id: 'common.link.text.high',
          })} ${resourceRiskQuantity?.highLevelRiskCount || 0}`}
        />
      </Button>
      <Button
        type={'link'}
        style={{ padding: 0 }}
        size={'small'}
        target={'_blank'}
        href={`/riskManagement/riskList?platform=${record?.platform}&riskLevel=${RiskLevelList[1].value}&resourceId=${record?.resourceId}`}
        rel={'prefetch'}
      >
        <LevelTag
          level={'MEDIUM'}
          text={`${intl.formatMessage({
            id: 'common.link.text.middle',
          })} ${resourceRiskQuantity?.mediumLevelRiskCount || 0}`}
        />
      </Button>
      <Button
        type={'link'}
        style={{ padding: 0 }}
        size={'small'}
        target={'_blank'}
        href={`/riskManagement/riskList?platform=${record?.platform}&riskLevel=${RiskLevelList[2].value}&resourceId=${record?.resourceId}`}
        rel={'prefetch'}
      >
        <LevelTag
          level={'LOW'}
          text={`${intl.formatMessage({
            id: 'common.link.text.low',
          })}  ${resourceRiskQuantity?.lowLevelRiskCount || 0}`}
        />
      </Button>
    </Space>
  );
};

// Asset Management
const AssetManagement: React.FC = () => {
  // Basic Attributes
  const { SHOW_CHILD } = Cascader;
  // Platform Rule Group List
  const { platformList } = useModel('rule');
  const searchParams: URLSearchParams = new URLSearchParams(
    useLocation()?.search,
  );
  // Cloud Account Query
  const cloudAccountIdQuery = searchParams.get('cloudAccountId');
  // Cloud platform query
  const platformQuery = searchParams.get('platform');
  // Resource Type Group Query
  const resourceGroupTypeQuery = searchParams.get('resourceGroupType');
  // Resource Type Query
  const resourceTypeQuery = searchParams.get('resourceType');
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Form Action
  const formActionRef = useRef<ProFormInstance>();
  // Asset Details Modal
  const [assetInformVisible, setAssetInformVisible] = useState<boolean>(false);
  // Form Instance
  const [form] = Form.useForm();
  // Intl API
  const intl = useIntl();
  // Account Drawer
  const [assetDrawerVisible, setAssetDrawerVisible] = useState<boolean>(false);
  // Risk information
  const assetDrawerRef = useRef<any>({});
  // Risk information
  const assetInfoRef = useRef<any>({});
  // List of Resource Types
  const [resourceTypeList, setResourceTypeList] = useState([]);
  // Custom ColumnsStateMap
  const [columnsStateMap] = useState({
    customField: {
      show: false,
    },
    cloudAccountId: {
      show: false,
    },
    platform: {
      show: false,
    },
    address: {
      show: false,
    },
    tenantName: {
      show: false,
    },
  });

  // According to the cloud platform, obtain a list of resource types
  const { run: requestResourceTypeList } = useRequest(
    (list: string[]) => {
      return queryGroupTypeList({ platformList: list });
    },
    {
      manual: true,
      formatResult: (result): void => {
        const { content } = result;
        setResourceTypeList((content as any) || []);
      },
    },
  );

  // Table Columns
  const columns: ProColumns<API.BaseAssetResultInfo, 'text'>[] = [
    {
      title: (
        <>
          {intl.formatMessage({
            id: 'common.table.columns.assetId',
          })}
          &nbsp;&nbsp;|&nbsp;&nbsp;
          {intl.formatMessage({
            id: 'common.table.columns.assetName',
          })}
        </>
      ),
      dataIndex: 'resourceId',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record: API.BaseAssetResultInfo) => (
        <>
          <Button
            style={{ padding: 0 }}
            size={'small'}
            type={'link'}
            onClick={(): void => {
              assetInfoRef.current = {
                ...record,
              };
              setAssetInformVisible(true);
            }}
          >
            <Paragraph copyable style={{ color: 'inherit', marginBottom: 0 }}>
              {record.resourceId}
            </Paragraph>
          </Button>
          <Disposition
            placement={'topLeft'}
            text={record.resourceName}
            maxWidth={360}
            style={{
              color: '#333',
            }}
          />
        </>
      ),
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.asset.type',
      }),
      dataIndex: 'resourceType',
      valueType: 'text',
      align: 'left',
      width: 200,
      hideInSearch: true,
      render: (_, record: API.BaseAssetResultInfo) => {
        return <ThemeTag text={record?.resourceType} />;
      },
    },
    {
      title: intl.formatMessage({
        id: 'asset.module.risk.number',
      }),
      width: 200,
      dataIndex: 'rulePassRate',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record: API.BaseAssetResultInfo) => {
        return <RiskQuantity record={record} />;
      },
    },
    {
      title: intl.formatMessage({
        id: 'common.input.text.custom.fields',
      }),
      dataIndex: 'customFieldValue',
      valueType: 'text',
      align: 'left',
      width: 500,
      render: (_, record: API.BaseAssetResultInfo) => {
        return (
          <div style={{ maxHeight: '120px', overflow: 'auto' }}>
            <Row>
              <Col span={24}>
                {isEmpty(record?.resourceDetailConfigMap?.['BASE_INFO']) &&
                isEmpty(record?.resourceDetailConfigMap?.['NETWORK']) ? (
                  '-'
                ) : (
                  <>
                    {record?.resourceDetailConfigMap?.['BASE_INFO']?.map(
                      (item: Record<string, any>, index: number) => {
                        return (
                          <Form.Item
                            key={index}
                            label={item?.name}
                            style={COMMON_STYLES.formItem}
                          >
                            <Paragraph
                              copyable={{ text: item.value }}
                              style={{
                                ...COMMON_STYLES.paragraph,
                                ...COMMON_STYLES.paragraphTable,
                              }}
                              ellipsis={{ tooltip: item.value }}
                            >
                              {item.value}
                            </Paragraph>
                          </Form.Item>
                        );
                      },
                    )}
                    {record?.resourceDetailConfigMap?.['NETWORK']?.map(
                      (item: Record<string, any>, index: number) => {
                        return (
                          <Form.Item
                            key={index}
                            label={item?.name}
                            style={COMMON_STYLES.formItem}
                          >
                            <Paragraph
                              copyable={{ text: item.value }}
                              style={{
                                ...COMMON_STYLES.paragraph,
                                ...COMMON_STYLES.paragraphTable,
                              }}
                              ellipsis={{ tooltip: item.value }}
                            >
                              {item.value}
                            </Paragraph>
                          </Form.Item>
                        );
                      },
                    )}
                  </>
                )}
              </Col>
            </Row>
          </div>
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'common.table.columns.createAndUpdateTime',
      }),
      dataIndex: 'gmt_modified',
      tooltip: intl.formatMessage({
        id: 'common.table.columns.sort.update',
      }),
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      sorter: true,
      width: 240,
      render: (_, record) => {
        return (
          <div>
            <section style={{ color: '#999' }}>
              {record?.gmtCreate || '-'}
            </section>
            <section style={{ color: '#999' }}>
              {record?.gmtModified || '-'}
            </section>
          </div>
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'common.select.label.cloudAccount',
      }),
      dataIndex: 'cloudAccountId',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record: API.BaseAssetResultInfo) => {
        return (
          <div>
            <div>{record?.cloudAccountId}</div>
            <div style={{ color: '#999' }}>{record?.alias}</div>
          </div>
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'common.select.label.cloudPlatform',
      }),
      dataIndex: 'platform',
      valueType: 'text',
      align: 'center',
      hideInSearch: true,
      render: (_, record: API.BaseAssetResultInfo) => {
        return obtainPlatformIcon(record.platform!, platformList);
      },
    },
    {
      title: intl.formatMessage({
        id: 'asset.module.input.text.ip',
      }),
      dataIndex: 'address',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
    },
    {
      title: intl.formatMessage({
        id: 'common.select.label.tenant',
      }),
      dataIndex: 'tenantName',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
    },
  ];

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
      manual: true,
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

  useEffect((): void => {
    const postBody: any = {};
    if (platformQuery) postBody.platformList = [platformQuery];
    if (cloudAccountIdQuery) postBody.cloudAccountSearch = cloudAccountIdQuery;
    requestCloudAccountBaseInfoList(postBody);
    if (
      !isEmpty(cloudAccountIdQuery) ||
      !isEmpty(platformQuery) ||
      (!isEmpty(resourceGroupTypeQuery) && !isEmpty(resourceTypeQuery))
    ) {
      if (cloudAccountIdQuery) {
        form?.setFieldValue('cloudAccountId', cloudAccountIdQuery);
      }
      if (!isEmpty(platformQuery)) {
        form?.setFieldValue('platformList', [platformQuery]);
        // Re request the corresponding resource type on the cloud platform
        form.setFieldValue('resourceTypeList', null);
        setResourceTypeList([]);
        requestResourceTypeList([platformQuery!]);
        if (!isEmpty(resourceGroupTypeQuery) && !isEmpty(resourceTypeQuery)) {
          const resourceTypeArray = [];
          const resourceTypeArrayValue = [
            resourceGroupTypeQuery,
            resourceTypeQuery,
          ];
          resourceTypeArray.push(resourceTypeArrayValue);
          form.setFieldValue('resourceTypeList', resourceTypeArray);
        }
      }
    }
  }, [platformQuery, cloudAccountIdQuery, resourceTypeQuery]);

  return (
    <PageContainer
      title={false}
      className={styles['assetPageContainer']}
      breadcrumb={undefined}
    >
      <ProCard
        bodyStyle={{ paddingBottom: 0 }}
        className={styles['customFilterCard']}
      >
        <Form form={form}>
          <Row gutter={[24, 10]}>
            <Col span={24}>
              <Form.Item
                name="platformList"
                label={intl.formatMessage({
                  id: 'common.select.label.cloudPlatform',
                })}
                style={{ marginBottom: 0 }}
              >
                <Checkbox.Group
                  options={valueListAddIcon(platformList)}
                  onChange={(checkedValue): void => {
                    form.setFieldValue('resourceTypeList', null);
                    setResourceTypeList([]);
                    requestResourceTypeList(checkedValue as any);
                    requestCloudAccountBaseInfoList({
                      platformList: (checkedValue as string[]) || [],
                    });
                  }}
                />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item
                name="resourceTypeList"
                label={intl.formatMessage({
                  id: 'cloudAccount.extend.title.asset.type',
                })}
                style={{ marginBottom: 0, width: '100%' }}
              >
                <Cascader
                  options={resourceTypeList}
                  multiple
                  placeholder={intl.formatMessage({
                    id: 'common.select.text.placeholder',
                  })}
                  showCheckedStrategy={SHOW_CHILD}
                  allowClear
                  showSearch
                />
              </Form.Item>
            </Col>
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
                name="searchParam"
                label={intl.formatMessage({
                  id: 'common.input.text.assetIdAndName',
                })}
                style={{ marginBottom: 0, width: '100%' }}
              >
                <Input
                  placeholder={intl.formatMessage({
                    id: 'common.input.text.placeholder',
                  })}
                  allowClear
                />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item
                name="address"
                label={intl.formatMessage({
                  id: 'asset.module.input.text.ip',
                })}
                style={{ marginBottom: 0, width: '100%' }}
              >
                <Input
                  placeholder={intl.formatMessage({
                    id: 'common.input.text.placeholder',
                  })}
                  allowClear
                />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </ProCard>
      <ProTable
        scroll={{ x: 'max-content' }}
        rowKey={'id'}
        search={{
          span: 6,
          labelWidth: 0,
        }}
        headerTitle={
          <div className={styleType['customTitle']}>
            {intl.formatMessage({
              id: 'asset.module.text.asset.inquiry',
            })}
          </div>
        }
        actionRef={tableActionRef}
        formRef={formActionRef}
        columns={columns}
        columnsState={{
          defaultValue: columnsStateMap,
          persistenceType: 'localStorage',
          persistenceKey: 'ASSET_TABLE_LIST_CACHE',
        }}
        onReset={(): void => {
          form.resetFields();
          formActionRef.current?.resetFields();
        }}
        pagination={{
          showQuickJumper: false,
          showSizeChanger: true,
          defaultPageSize: 10,
          defaultCurrent: 1,
          pageSizeOptions: [10, 20, 50],
        }}
        request={async (
          params: Record<string, any>,
          sort: Record<string, any>,
        ): Promise<any> => {
          const {
            customFieldValue, // Custom Fields
            current,
            pageSize,
          } = params;
          // Request body parameters
          const postBody: Record<string, any> = {
            customFieldValue, // Custom Fields
            page: current,
            size: pageSize,
          };
          // When there is field sorting
          const sorter = obtainFirstProperty(sort);
          // There are sorting parameters present
          if (!isEmpty(sorter)) {
            postBody.sortParam = sorter?.key;
            // @ts-ignore
            postBody.sortType = AssetSortMethodMap[sorter!.value];
          }
          // Cloud Platform List
          const platformList = form.getFieldValue('platformList');
          if (!isEmpty(platformList)) postBody.platformList = platformList;
          // Asset Type List
          const resourceTypeList = form.getFieldValue('resourceTypeList');
          if (!isEmpty(resourceTypeList))
            postBody.resourceTypeList = resourceTypeList;
          // Cloud Account ID
          const cloudAccountId = form.getFieldValue('cloudAccountId');
          if (!isEmpty(cloudAccountId))
            postBody.cloudAccountId = cloudAccountId;
          // ResourceName | ResourceId
          const searchParam = form.getFieldValue('searchParam');
          if (searchParam) postBody.searchParam = searchParam;
          // IP Address
          const address = form.getFieldValue('address');
          if (address) postBody.address = address;
          // Interface Request
          const { content, code } = await queryResourceList(postBody);
          const { data, total } = content;
          return {
            data: data || [],
            total: total || 0,
            success: code === 200 || false,
          };
        }}
        tableClassName={styles['customAssetTable']}
        expandable={{
          expandedRowRender: (record: API.BaseAssetResultInfo) => (
            <Row>
              <Col
                span={2}
                className={styles['dimBlock']}
                style={{ borderLeft: '0.5px solid rgb(239, 239, 239)' }}
              >
                {intl.formatMessage({
                  id: 'common.select.label.cloudAccount',
                })}
              </Col>
              <Col
                span={4}
                className={styles['cleanBlock']}
                style={{ flexDirection: 'column' }}
              >
                <div>{record?.cloudAccountId}</div>
                <div style={{ color: '#999' }}>{record?.alias}</div>
              </Col>
              <Col span={2} className={styles['dimBlock']}>
                {intl.formatMessage({
                  id: 'common.select.label.cloudPlatform',
                })}
              </Col>
              <Col span={4} className={styles['cleanBlock']}>
                {obtainPlatformIcon(record.platform!, platformList)}
              </Col>
              <Col span={2} className={styles['dimBlock']}>
                {intl.formatMessage({
                  id: 'asset.module.input.text.ip',
                })}
              </Col>
              <Col span={4} className={styles['cleanBlock']}>
                {record?.address || '-'}
              </Col>
              <Col span={2} className={styles['dimBlock']}>
                {intl.formatMessage({
                  id: 'common.select.label.tenant',
                })}
              </Col>
              <Col span={4} className={styles['cleanBlock']}>
                {record?.tenantName || '-'}
              </Col>
              <Col
                span={2}
                className={styles['dimBlock']}
                style={{
                  borderTop: 'none',
                  borderLeft: '0.5px solid rgb(239, 239, 239)',
                }}
              >
                {intl.formatMessage({
                  id: 'common.input.text.custom.fields',
                })}
              </Col>
              <Col
                span={22}
                className={styles['customField']}
                style={{
                  borderTop: 'none',
                }}
              >
                <Row>
                  <Col span={22} style={{ maxHeight: '200px', overflow: 'auto' }}>
                    {isEmpty(record?.resourceDetailConfigMap?.['BASE_INFO']) &&
                    isEmpty(record?.resourceDetailConfigMap?.['NETWORK']) ? (
                      <ConfigProvider
                        theme={{
                          token: {
                            margin: 8,
                            marginXL: 8,
                            marginXS: 8,
                          },
                        }}
                      >
                        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                      </ConfigProvider>
                    ) : (
                      <>
                        {record?.resourceDetailConfigMap?.['BASE_INFO']?.map(
                          (item: Record<string, any>, index: number) => {
                            return (
                              <Form.Item
                                key={index}
                                label={item?.name}
                                style={COMMON_STYLES.formItem}
                              >
                                <Paragraph
                                  copyable={{ text: item.value }}
                                  style={{
                                    ...COMMON_STYLES.paragraph,
                                    ...COMMON_STYLES.paragraphExpanded,
                                  }}
                                  ellipsis={{ tooltip: item.value }}
                                >
                                  {item.value}
                                </Paragraph>
                              </Form.Item>
                            );
                          },
                        )}
                        {record?.resourceDetailConfigMap?.['NETWORK']?.map(
                          (item: Record<string, any>, index: number) => {
                            return (
                              <Form.Item
                                key={index}
                                label={item?.name}
                                style={COMMON_STYLES.formItem}
                              >
                                <Paragraph
                                  copyable={{ text: item.value }}
                                  style={{
                                    ...COMMON_STYLES.paragraph,
                                    ...COMMON_STYLES.paragraphExpanded,
                                  }}
                                  ellipsis={{ tooltip: item.value }}
                                >
                                  {item.value}
                                </Paragraph>
                              </Form.Item>
                            );
                          },
                        )}
                      </>
                    )}
                  </Col>
                  <Col span={2}>
                    <Button
                      size={'small'}
                      type={'link'}
                      target={'_self'}
                      href={`/assetManagement/asseConfig?id=${record?.id}`}
                    >
                      <EditOutlined />
                      {intl.formatMessage({
                        id: 'common.button.text.edit',
                      })}
                    </Button>
                  </Col>
                </Row>
              </Col>
            </Row>
          ),
          columnTitle: <div style={{ width: 30, textAlign: 'center' }} />,
          columnWidth: 30,
          rowExpandable: (): boolean => true,
          expandIcon: ExpandIcon,
        }}
      />

      <AssetDrawer // Resource details - not yet used
        assetDrawerVisible={assetDrawerVisible}
        setAssetDrawerVisible={setAssetDrawerVisible}
        assetDrawerInfo={assetDrawerRef.current}
        tableActionRef={tableActionRef}
      />

      <AssetInform // Resource Details
        assetInformVisible={assetInformVisible}
        setAssetInformVisible={setAssetInformVisible}
        assetInfo={assetInfoRef.current}
      />
    </PageContainer>
  );
};

export default AssetManagement;

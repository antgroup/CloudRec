import DEFAULT_RESOURCE_ICON from '@/assets/images/DEFAULT_RESOURCE_ICON.svg';
import ExistTag from '@/components/Common/ExistTag';
import ThemeTag from '@/components/Common/ThemeTag';
import styleType from '@/components/Common/index.less';
import Disposition from '@/components/Disposition';
import DispositionPro from '@/components/DispositionPro';
import IgnoreRiskForm from '@/pages/RiskManagement/components/IgnoreRiskForm';
import RiskDrawer from '@/pages/RiskManagement/components/RiskDrawer';
import {
  AssetStatusList,
  IgnoreReasonTypeList,
  RiskStatusList,
} from '@/pages/RiskManagement/const';
import EditDrawerForm from '@/pages/RuleManagement/WhiteList/components/EditDrawerForm';
import { cloudAccountBaseInfoList } from '@/services/account/AccountController';
import { queryGroupTypeList } from '@/services/resource/ResourceController';
import {
  cancelIgnoreRisk,
  exportRiskList,
  listRuleStatistics,
  queryRiskList,
} from '@/services/risk/RiskController';
import { RangePresets, RiskLevelList } from '@/utils/const';
import {
  BlobExportXLSXFn,
  obtainPlatformEasyIcon,
  obtainRiskLevel,
  obtainRiskLevelColor,
  obtainRiskStatus,
  valueListAddIcon,
  valueListAddTag,
  valueListAsValueEnum,
} from '@/utils/shared';
import { SearchOutlined } from '@ant-design/icons';
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
  Breakpoint,
  Button,
  Cascader,
  Checkbox,
  Col,
  Divider,
  Flex,
  Form,
  Grid,
  Popconfirm,
  Row,
  Select,
  Spin,
  Tag,
  message,
} from 'antd';
import { debounce, isEmpty } from 'lodash';
import React, { useEffect, useMemo, useRef, useState } from 'react';
import styles from './index.less';
const { useBreakpoint } = Grid;
const { SHOW_CHILD } = Cascader;

// risk management
const RiskManagement: React.FC = () => {
  // Ant Design Provide monitoring of screen width changes
  const breakpoints: Partial<Record<Breakpoint, boolean>> = useBreakpoint();
  // Platform Rule Group List
  const { platformList, ruleGroupList, ruleTypeList, allRuleList } =
    useModel('rule');
  // Query Data
  const { search } = useLocation();
  const searchParams: URLSearchParams = new URLSearchParams(search);
  // Risk level
  const riskLevelQuery = searchParams.get('riskLevel');
  // platform
  const platformQuery = searchParams.get('platform');
  // Rule Code
  const ruleCodeQuery = searchParams.get('ruleCode');
  // Resource Id
  const resourceIdQuery = searchParams.get('resourceId');
  // Message Instance
  const [messageApi, contextHolder] = message.useMessage();
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Form Action
  const formActionRef = useRef<ProFormInstance>();
  // FormInstance
  const [form] = Form.useForm();
  // Intl API
  const intl = useIntl();
  // AccountDrawer
  const [riskDrawerVisible, setRiskDrawerVisible] = useState<boolean>(false);
  // Risk information
  const riskDrawerRef = useRef<any>({});
  // Ignore risk
  const [ignoreRiskFormVisible, setIgnoreRiskFormVisible] = useState(false);
  // Risk Info Data
  const riskInfoRef = useRef<any>({});
  // White List Rule Info
  const whiteListInfoRef = useRef<API.BaseWhiteListRuleInfo>({});
  // White List Drawer Visible
  const [editWhiteDrawerVisible, setEditWhiteDrawerVisible] =
    useState<boolean>(false);
  // Filter Factor
  const [filterFactor, setFilterFactor] = useState({});
  // Risk status
  const [status, setStatus] = useState<string>(
    RiskStatusList[0]?.value as string,
  );
  // Export file Loading
  const [exportLoading, setExportLoading] = useState<boolean>(false);
  // Cancel ignoring risks
  const onClickCancelIgnoreRisk = async (record: API.BaseRiskResultInfo) => {
    const postBody = {
      riskId: record.id!,
    };
    const r = await cancelIgnoreRisk(postBody);
    if (r.code === 200 && r.msg === 'success') {
      messageApi.success(
        intl.formatMessage({
          id: 'risk.message.api.cancel.ignore.risk.success',
        }),
      );
      tableActionRef?.current?.reload();
    }
  };

  // List of Resource Types
  const [resourceTypeList, setResourceTypeList] = useState<any[]>([]);

  // According to the cloud platform, obtain a list of resource types
  const { run: requestResourceTypeList } = useRequest(
    (list: string[]) => {
      return queryGroupTypeList({ platformList: list });
    },
    {
      manual: true,
      formatResult: (result: API.Result_PlatformInfo_): void => {
        const { content } = result;
        setResourceTypeList((content as any) || []);
      },
    },
  );

  useEffect((): void => {
    // Cloud platform
    if (!isEmpty(platformQuery)) {
      form?.setFieldValue('platformList', [platformQuery]);
      // Re request the corresponding resource type on the cloud platform
      form.setFieldValue('resourceType', null);
      setResourceTypeList([]);
      requestResourceTypeList([platformQuery!]);
    }
    // Risk Level
    if (!isEmpty(riskLevelQuery)) {
      form?.setFieldValue('riskLevelList', [riskLevelQuery]);
    }
    // Rule Name
    if (!isEmpty(ruleCodeQuery)) {
      formActionRef.current?.setFieldValue('ruleCodeList', [ruleCodeQuery]);
    }
    // Resource Id
    if (!isEmpty(resourceIdQuery)) {
      formActionRef.current?.setFieldValue('resourceId', resourceIdQuery);
    }
  }, [platformQuery, riskLevelQuery, ruleCodeQuery, resourceIdQuery]);

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

  const {
    data: riskListGroupByRuleNameList,
    run: requestRiskListGroupByRuleName,
  } = useRequest(
    (params: API.RiskInfo) => {
      return listRuleStatistics({ ...params });
    },
    {
      manual: true,
      formatResult: (r) => {
        let array = [];
        array = r?.content?.map((item: Record<string, any>) => {
          return {
            label: (
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>{item?.ruleName}</span>
                <Flex align={'center'}>
                  <Tag
                    color={obtainRiskLevelColor(RiskLevelList, item?.riskLevel)}
                    style={{ margin: '0 0 0 8px' }}
                  >
                    {item?.count || '-'}
                  </Tag>
                </Flex>
              </div>
            ),
            value: item.ruleId,
          };
        });
        return array;
      },
    },
  );

  const onClickExportRiskList = async () => {
    const postBody = {
      status: status,
      ...form?.getFieldsValue(),
      ...formActionRef?.current?.getFieldsValue(),
    };
    setExportLoading(true);
    exportRiskList({ ...postBody }, { responseType: 'blob' })
      .then((r) => {
        if (r.type === 'application/json') {
          const reader = new FileReader();
          reader.onload = () => {
            try {
              const errorData = JSON.parse(reader.result as string);
              messageApi.error(errorData.msg || intl.formatMessage({ id: 'common.message.text.export.failed' }));
            } catch (e) {
              messageApi.error(intl.formatMessage({ id: 'common.message.text.export.failed' }));
            }
          };
          reader.readAsText(r);
        } else {
          BlobExportXLSXFn(
            r,
            `CloudRec ${intl.formatMessage({
              id: 'risk.module.text.risk.data',
            })}`,
          );
          messageApi.success(
            intl.formatMessage({ id: 'common.message.text.export.success' }),
          );
        }
      })
      .catch((error) => {
        messageApi.error(intl.formatMessage({ id: 'common.message.text.export.failed' }));
        console.error('Export failed:', error);
      })
      .finally(() => setExportLoading(false));
  };

  // Table Column Search
  const [ruleIdList, setRuleIdList] = useState<Array<number>>();

  const handleFilterDropdownVisibleChange = async (visible: boolean) => {
    if (visible) {
      const postBody = {
        status: status,
        ...form?.getFieldsValue(),
        ...formActionRef?.current?.getFieldsValue(),
      };
      await requestRiskListGroupByRuleName(postBody);
    }
  };

  const getColumnSearchProps = () => ({
    filterDropdown: ({ confirm }: { confirm: any }) => {
      return (
        <div style={{ padding: 8 }} onKeyDown={(e) => e.stopPropagation()}>
          <Select
            maxTagCount={'responsive'}
            allowClear
            mode={'multiple'}
            placeholder={intl.formatMessage({
              id: 'common.select.text.placeholder',
            })}
            popupMatchSelectWidth={false}
            options={riskListGroupByRuleNameList || []}
            onChange={debounce((value): void => {
              setRuleIdList(value);
              confirm();
            }, 1000)}
            style={{ minWidth: 180 }}
          />
        </div>
      );
    },
    filterDropdownProps: {
      onOpenChange: handleFilterDropdownVisibleChange,
    },
    filterIcon: (filtered: boolean) => (
      <SearchOutlined style={{ color: filtered ? '#1677ff' : undefined }} />
    ),
    destroyOnClose: true,
  });

  const onClickAddInWhiteList = (record: API.BaseWhiteListRuleInfo) => {
    setEditWhiteDrawerVisible(true);
    whiteListInfoRef.current = record;
  };

  // Table Columns
  const columns: ProColumns<API.BaseRiskResultInfo, 'text'>[] = [
    {
      title: intl.formatMessage({
        id: 'home.module.inform.columns.ruleName',
      }),
      dataIndex: 'ruleName',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record: API.BaseRiskResultInfo) => {
        return (
          <Flex align={'center'}>
            <img
              src={record?.icon || DEFAULT_RESOURCE_ICON}
              alt="RESOURCE_ICON"
              style={{ width: 18, height: 18 }}
            />
            <Disposition
              text={record?.ruleVO?.ruleName || '-'}
              maxWidth={breakpoints?.xxl ? 280 : 240}
              rows={1}
              style={{
                color: '#333',
                fontSize: 14,
                marginLeft: 8,
              }}
              placement={'topLeft'}
            />
          </Flex>
        );
      },
      ...getColumnSearchProps(),
    },
    {
      title: intl.formatMessage({
        id: 'home.module.inform.columns.ruleName',
      }),
      dataIndex: 'ruleCodeList',
      valueType: 'select',
      valueEnum: valueListAsValueEnum(allRuleList),
      hideInTable: true,
      fieldProps: {
        mode: 'multiple',
      },
    },
    {
      title: intl.formatMessage({
        id: 'risk.module.text.firstAndLast.discovered',
      }),
      dataIndex: 'gmtCreated',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
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
        id: 'risk.module.text.ignore.type',
      }),
      dataIndex: 'ignoreReasonTypeList',
      valueType: 'checkbox',
      valueEnum: valueListAsValueEnum(IgnoreReasonTypeList),
      align: 'left',
      hideInTable: true,
      hideInSearch: status !== 'IGNORED',
    },
    {
      title: intl.formatMessage({
        id: 'layout.routes.title.ruleGroup',
      }),
      dataIndex: 'ruleGroupIdList',
      valueType: 'select',
      valueEnum: valueListAsValueEnum(ruleGroupList),
      hideInTable: true,
      fieldProps: {
        mode: 'multiple',
      },
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.asset.type',
      }),
      dataIndex: 'resourceTypeList',
      valueType: 'cascader',
      align: 'left',
      hideInTable: true,
      fieldProps: {
        multiple: true,
        showCheckedStrategy: SHOW_CHILD,
        options: resourceTypeList,
        showSearch: true,
        allowClear: true,
      },
    },
    {
      title: intl.formatMessage({
        id: 'home.module.inform.columns.ruleTypeName',
      }),
      dataIndex: 'ruleTypeIdList',
      valueType: 'cascader',
      hideInTable: true,
      fieldProps: {
        multiple: true,
        options: ruleTypeList,
        showCheckedStrategy: SHOW_CHILD,
        fieldNames: {
          label: 'typeName',
          value: 'id',
          children: 'childList',
        },
      },
    },
    {
      title: intl.formatMessage({
        id: 'common.select.label.cloudAccount',
      }),
      dataIndex: 'cloudAccountId',
      valueType: 'select',
      fieldProps: {
        placeholder: intl.formatMessage({
          id: 'common.select.query.text.placeholder',
        }),
        showSearch: true,
        notFoundContent: fetching && <Spin size="small" />,
        onSearch: debounceFetcher,
        options: baseCloudAccountList || [],
      },
      align: 'left',
      render: (_, record) => {
        return (
          <div>
            <section style={{ color: 'rgb(51, 51, 51)' }}>
              {record?.cloudAccountId || '-'}
            </section>
            <Flex style={{ fontSize: '12px', color: '#999' }}>
              {obtainPlatformEasyIcon(record.platform!, platformList)}
              {record?.alias || '-'}
            </Flex>
          </div>
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.asset.type',
      }),
      dataIndex: 'resourceType',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record: API.BaseRiskResultInfo) => {
        return <ThemeTag text={record?.resourceType} />;
      },
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.asset.name',
      }),
      dataIndex: 'resourceName',
      valueType: 'text',
      align: 'left',
      width: 200,
      render: (_, record: API.BaseRiskResultInfo) => {
        return (
          <>
            <DispositionPro
              placement={'topLeft'}
              maxWidth={400}
              rows={1}
              text={
                <>
                  {record.resourceName || '-'}
                  <ExistTag status={record?.resourceStatus} />
                </>
              }
              tooltipText={
                record?.resourceStatus === AssetStatusList[1].value
                  ? `(${intl.formatMessage({
                      id: 'risk.module.text.not.exist',
                    })}) ` + record.resourceName
                  : record.resourceName || '-'
              }
            />
          </>
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'common.table.columns.assetId',
      }),
      dataIndex: 'resourceId',
      valueType: 'text',
      align: 'left',
      hideInTable: true,
    },
    {
      title: intl.formatMessage({
        id: 'common.table.columns.assetStatus',
      }),
      dataIndex: 'resourceStatus',
      valueType: 'select',
      valueEnum: valueListAsValueEnum(AssetStatusList),
      align: 'left',
      hideInTable: true,
    },
    {
      title: intl.formatMessage({
        id: 'risk.module.text.first.discovery',
      }),
      dataIndex: 'createTimeRange',
      valueType: 'dateTimeRange',
      hideInTable: true,
      fieldProps: {
        presets: RangePresets,
      },
      search: {
        transform: (value: Array<string>) => ({
          gmtCreateStart: value[0],
          gmtCreateEnd: value[1],
        }),
      },
    },
    {
      title: intl.formatMessage({
        id: 'risk.module.text.recently.discovery',
      }),
      dataIndex: 'modifiedTimeRange',
      valueType: 'dateTimeRange',
      hideInTable: true,
      fieldProps: {
        presets: RangePresets,
      },
      search: {
        transform: (value: Array<string>) => ({
          gmtModifiedStart: value[0],
          gmtModifiedEnd: value[1],
        }),
      },
    },
    {
      title: intl.formatMessage({
        id: 'home.module.inform.columns.riskLevel',
      }),
      dataIndex: 'riskLevel',
      valueType: 'text',
      align: 'center',
      hideInSearch: true,
      render: (_, record: API.BaseRiskResultInfo) => {
        return obtainRiskLevel(
          RiskLevelList,
          record?.ruleVO?.riskLevel as string,
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'risk.module.text.risk.status',
      }),
      dataIndex: 'status',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record: API.BaseRiskResultInfo) => {
        return obtainRiskStatus(RiskStatusList, record?.status as string);
      },
    },
    {
      title: intl.formatMessage({
        id: 'risk.module.text.ignore.reason',
      }),
      dataIndex: 'ignoreReason',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      hideInTable: status !== 'IGNORED',
      render: (_, record: API.BaseRiskResultInfo) => {
        return (
          <Disposition
            placement={'topLeft'}
            text={record.ignoreReason || '-'}
            maxWidth={210}
          />
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'risk.module.text.ignore.type',
      }),
      dataIndex: 'ignoreReasonType',
      valueType: 'select',
      valueEnum: valueListAsValueEnum(IgnoreReasonTypeList),
      align: 'left',
      hideInSearch: true,
      hideInTable: status !== 'IGNORED',
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.cloud.operate',
      }),
      dataIndex: 'option',
      valueType: 'option',
      align: 'center',
      fixed: 'right',
      render: (_, record: API.BaseRiskResultInfo) => (
        <>
          {!['WHITED']?.includes(record.status!) && (
            <>
              <Button
                size={'small'}
                type="link"
                onClick={(): void =>
                  onClickAddInWhiteList({ riskId: record?.id })
                }
              >
                {intl.formatMessage({
                  id: 'common.button.text.white',
                })}
              </Button>
              <Divider type={'vertical'} />
            </>
          )}
          {record.status === 'IGNORED' ? (
            <Popconfirm
              title={<></>}
              description={intl.formatMessage({
                id: 'risk.module.text.cancel.ignore',
              })}
              onConfirm={() => onClickCancelIgnoreRisk(record)}
              onCancel={() => {}}
              okText={intl.formatMessage({
                id: 'common.button.text.ok',
              })}
              cancelText={intl.formatMessage({
                id: 'common.button.text.cancel',
              })}
            >
              <Button size={'small'} type="link">
                {intl.formatMessage({
                  id: 'common.button.text.cancelIgnore',
                })}
              </Button>
            </Popconfirm>
          ) : (
            <Button
              size={'small'}
              type="link"
              onClick={(): void => {
                riskInfoRef.current = {
                  ...record,
                };
                setIgnoreRiskFormVisible(true);
              }}
            >
              {intl.formatMessage({
                id: 'common.button.text.ignore',
              })}
            </Button>
          )}
          <Divider type={'vertical'} />
          <Button
            size={'small'}
            type="link"
            target={'_self'}
            onClick={() => {
              setRiskDrawerVisible(true);
              riskDrawerRef.current = {
                ...record,
              };
            }}
          >
            {intl.formatMessage({
              id: 'common.button.text.detail',
            })}
          </Button>
        </>
      ),
    },
  ];

  const requestTableList = async (params: Record<string, any>) => {
    const {
      pageSize,
      current,
      ruleId, // ruleId
      ruleGroupIdList, // ruleGroupIdList
      cloudAccountId, // cloudAccountId
      resourceName, // resourceName
      resourceTypeList, // resourceTypeList
      status = 'UNREPAIRED', // Risk status
      ignoreReasonTypeList, // Ignore type
      ruleTypeIdList,
      ruleIdList, // Table rule name filtering
      gmtCreateStart, // Start time of risk creation
      gmtCreateEnd, // End time of risk creation
      gmtModifiedStart, // Start time of risk update
      gmtModifiedEnd, // End time of risk update
      resourceStatus, // Resource status
    } = params;
    // Cloud platform
    const platformList = form.getFieldValue('platformList');
    // Risk level
    const riskLevelList = form.getFieldValue('riskLevelList');
    // Rule Name
    const ruleCodeList = formActionRef.current?.getFieldValue('ruleCodeList');
    // Resource Id
    const resourceId = formActionRef.current?.getFieldValue('resourceId');
    const postBody: Record<string, any> = {
      page: current,
      size: pageSize,
      ruleId,
      ruleGroupIdList,
      cloudAccountId,
      resourceName,
      resourceTypeList,
      status,
      ignoreReasonTypeList,
      ruleTypeIdList,
      gmtCreateStart,
      gmtCreateEnd,
      gmtModifiedStart,
      gmtModifiedEnd,
      resourceStatus,
    };
    if (platformList) postBody.platformList = platformList;
    if (riskLevelList) postBody.riskLevelList = riskLevelList;
    if (ruleCodeList) postBody.ruleCodeList = ruleCodeList;
    if (resourceId) postBody.resourceId = resourceId;
    if (ruleIdList && !isEmpty(ruleIdList)) postBody.ruleIdList = ruleIdList;
    const { content, code } = await queryRiskList(postBody);
    return {
      data: content?.data || [],
      total: content?.total || 0,
      success: code === 200 || false,
    };
  };

  return (
    <PageContainer
      title={false}
      className={styles['riskPageContainer']}
      breadcrumbRender={false}
    >
      {contextHolder}
      <ProCard
        bodyStyle={{ paddingBlock: 0 }}
        className={styles['customFilterCard']}
        tabs={{
          activeKey: status,
          items:
            (RiskStatusList.map((item) => ({
              label: item.label,
              key: item.value,
              children: (
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
                    <Col span={24}>
                      <Form.Item
                        name="riskLevelList"
                        label={intl.formatMessage({
                          id: 'home.module.inform.columns.riskLevel',
                        })}
                        style={{ marginBottom: 0 }}
                      >
                        <Checkbox.Group
                          options={valueListAddTag(RiskLevelList)}
                        />
                      </Form.Item>
                    </Col>
                  </Row>
                </Form>
              ),
            })) as any) || [],
          onChange: (key) => {
            setStatus(key as string);
            formActionRef.current?.setFieldValue('ignoreReasonTypeList', []);
            // Reset some filtering criteria
            formActionRef.current?.resetFields();
            form.setFieldValue('platformList', []);
            form.setFieldValue('riskLevelList', null);
            // @ts-ignore
            tableActionRef.current?.reset();
            // Trigger a re request for TableList
            setFilterFactor({
              status: key,
            });
          },
        }}
      />
      <ProTable
        scroll={{ x: 'max-content' }}
        rowKey={'id'}
        search={{
          span: 6,
          defaultCollapsed: false, // Default Expand
          collapseRender: false, // Hide expand/close button
          labelWidth: 0,
        }}
        headerTitle={
          <div className={styleType['customTitle']}>
            {intl.formatMessage({
              id: 'risk.module.text.risk.inquiry',
            })}
          </div>
        }
        toolBarRender={() => [
          <Button
            key="export"
            type="primary"
            loading={exportLoading}
            onClick={onClickExportRiskList}
          >
            {intl.formatMessage({
              id: 'common.button.text.export',
            })}
          </Button>,
        ]}
        actionRef={tableActionRef}
        formRef={formActionRef}
        columns={columns}
        request={requestTableList}
        onReset={(): void => {
          form.resetFields();
          setFilterFactor({});
        }}
        onSubmit={(): void => {
          const customFormData = form.getFieldsValue();
          setFilterFactor({
            ...filterFactor,
            ...customFormData,
          });
        }}
        params={{ ...filterFactor, ruleIdList }}
        pagination={{
          showQuickJumper: false,
          showSizeChanger: true,
          defaultPageSize: 10,
          defaultCurrent: 1,
        }}
      />

      <RiskDrawer // Risk Details
        locate={'risk'}
        riskDrawerVisible={riskDrawerVisible}
        setRiskDrawerVisible={setRiskDrawerVisible}
        riskDrawerInfo={riskDrawerRef.current}
        tableActionRef={tableActionRef}
      />

      <IgnoreRiskForm // Ignore risk
        ignoreRiskFormVisible={ignoreRiskFormVisible}
        setIgnoreRiskFormVisible={setIgnoreRiskFormVisible}
        riskInfo={riskInfoRef.current}
        tableActionRef={tableActionRef}
      />

      <EditDrawerForm
        editDrawerVisible={editWhiteDrawerVisible}
        setEditDrawerVisible={setEditWhiteDrawerVisible}
        whiteListDrawerInfo={whiteListInfoRef.current}
        tableActionRef={tableActionRef}
      />
    </PageContainer>
  );
};

export default RiskManagement;

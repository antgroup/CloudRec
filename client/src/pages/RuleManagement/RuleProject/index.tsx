import ThemeTag from '@/components/Common/ThemeTag';
import styleType from '@/components/Common/index.less';
import Disposition from '@/components/Disposition';
import DispositionPro from '@/components/DispositionPro';
import { queryGroupTypeList } from '@/services/resource/ResourceController';
import {
  changeRuleStatus,
  copyRule,
  deleteRule,
  queryExportRuleList,
  queryRuleList,
  scanByRule,
  loadRuleFromGithub,
} from '@/services/rule/RuleController';
import { RiskLevelList } from '@/utils/const';
import {
  BlobExportZIPFn,
  obtainFirstProperty,
  obtainPlatformEasyIcon,
  obtainRiskLevel,
  valueListAddIcon,
  valueListAddTag,
  valueListAsValueEnum,
} from '@/utils/shared';
import {
  DownCircleOutlined,
  EditOutlined,
  MoreOutlined,
  RightCircleOutlined,
} from '@ant-design/icons';
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
  Form,
  Grid,
  message,
  Popconfirm,
  Popover,
  Row,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
} from 'antd';
import { MessageType } from 'antd/es/message/interface';
import { isEmpty } from 'lodash';
import React, { useEffect, useRef, useState } from 'react';
import EditModalForm from './components/EditModalForm';
import styles from './index.less';
const { SHOW_CHILD } = Cascader;
const { useBreakpoint } = Grid;

// Rule Name Custom-Filter-Option
const filterOption = (
  input: string,
  item: { [key: string]: string },
): boolean => item.label?.includes(input);

const RuleProject: React.FC = () => {
  // Global Props
  const { platformList, ruleTypeList, allRuleList, ruleGroupList } =
    useModel('rule');
  // URL Query
  const { search } = useLocation();
  const searchParams: URLSearchParams = new URLSearchParams(search);
  // Rule group query
  let groupIdQuery = searchParams.get('groupId');
  // Rule Name Query
  let ruleCodeQuery = searchParams.get('ruleCode');
  // Platform Query
  let platformQuery = searchParams.get('platform');
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Ant Design Provide monitoring of screen width changes
  const breakpoints: Partial<Record<Breakpoint, boolean>> = useBreakpoint();
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Form Action
  const formActionRef = useRef<ProFormInstance>();
  // FormInstance
  const [form] = Form.useForm();
  // Intl API
  const intl = useIntl();
  // New | Edit Modal Form Visible
  const [editFormVisible, setEditFormVisible] = useState<boolean>(false);
  // Rule group information
  const projectInfoRef = useRef<any>({});
  // Sync Rules Popover Visible
  const [popoverVisible, setPopoverVisible] = useState<boolean>(false);
  // Sync Rules Loading Status
  const [syncLoading, setSyncLoading] = useState<boolean>(false);
  // Select status Table Row
  const [activeRow, setActiveRow] = useState<number>();
  // Scanning Loading
  const [scanLoading, setScanLoading] = useState<any>({});
  // Copy Loading
  const [copyLoading, setCopyLoading] = useState<any>({});
  // Export Loading
  const [exportLoading, setExportLoading] = useState<boolean>(false);
  // Selected Row Keys
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  // Custom ColumnsStateMap
  const [columnsStateMap] = useState({
    lastScanTime: {
      show: false,
    },
    groupName: {
      show: false,
    },
    gmtCreated: {
      show: false,
    },
  });
  // Current activation item Row
  const activeRowType = (record: Record<string, any>): string => {
    return record.id === activeRow ? 'ant-table-row-selected' : '';
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
      formatResult: (result): void => {
        const { content } = result;
        setResourceTypeList((content as any) || []);
      },
    },
  );
  // Delete selected rule
  const onClickDelRule = async (id: number): Promise<void> => {
    const hide: MessageType = messageApi.loading(
      intl.formatMessage({ id: 'common.message.text.delete.loading' }),
    );
    const result = await deleteRule({ id });
    hide();
    if (result.code === 200 || result.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.delete.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  // Detection
  const onClickScanByRule = async (id: number): Promise<void> => {
    setScanLoading({ ...scanLoading, [id]: true });
    const hide: MessageType = messageApi.loading(
      intl.formatMessage({ id: 'common.message.text.execute.loading' }),
    );
    const result = await scanByRule({ id });
    setScanLoading({ ...scanLoading, [id]: false });
    hide();
    if (result.code === 200 || result.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.execute.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  // Copy
  const onClickCopyByRule = async (id: number): Promise<void> => {
    setCopyLoading({ ...copyLoading, [id]: true });
    const hide: MessageType = messageApi.loading(
      intl.formatMessage({ id: 'common.message.text.copy.loading' }),
    );
    const result = await copyRule({ id });
    setCopyLoading({ ...copyLoading, [id]: false });
    hide();
    if (result.code === 200 || result.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.copy.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  // Disable rule modification status
  const onClickChangeRuleStatus = async (
    id: number,
    status: string,
  ): Promise<void> => {
    const postBody = {
      id,
      status,
    };
    const res = await changeRuleStatus(postBody);
    if (res.code === 200 || res.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.edit.success' }),
      );
      tableActionRef.current?.reloadAndRest?.();
    }
  };

  const onClickExportRuleList = (selectedRowKeys?: React.Key[]) => {
    setExportLoading(true);

    queryExportRuleList(
      selectedRowKeys ? { idList: selectedRowKeys } : {},
      { responseType: 'blob' }
    )
      .then((r) => {
        BlobExportZIPFn(
          r,
          `CloudRec ${intl.formatMessage({
            id: 'rule.module.text.rule.data',
          })}`,
        );
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.export.success' }),
        );
      })
      .finally(() => setExportLoading(false));
  };

  useEffect((): void => {
    // Group Name
    if (!isEmpty(groupIdQuery)) {
      form.setFieldValue('ruleGroupIdList', [Number(groupIdQuery)]);
    }
    // Rule Name
    if (!isEmpty(ruleCodeQuery)) {
      form.setFieldValue('ruleCodeList', [ruleCodeQuery]);
    }
    // Cloud Platform
    if (!isEmpty(platformQuery)) {
      form.setFieldValue('platformList', [platformQuery]);
      requestResourceTypeList([platformQuery!]);
    }
  }, [groupIdQuery, ruleCodeQuery, platformQuery]);

  const columns: ProColumns<API.RuleProjectInfo, 'text'>[] = [
    {
      title: intl.formatMessage({
        id: 'home.module.inform.columns.ruleName',
      }),
      dataIndex: 'ruleName',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record: API.RuleProjectInfo) => {
        return (
          <div>
            <DispositionPro
              placement={'topLeft'}
              maxWidth={breakpoints?.xxl ? 600 : 400}
              rows={1}
              text={record?.ruleName || '-'}
              tooltipText={
                <div>
                  <div>
                    {intl.formatMessage({
                      id: 'rule.module.text.rule.code',
                    })}
                    &nbsp;: {record?.ruleCode || '-'}
                  </div>
                  <div>
                    {intl.formatMessage({
                      id: 'home.module.inform.columns.ruleName',
                    })}
                    &nbsp;: {record?.ruleName || '-'}
                  </div>
                  <div>
                    {intl.formatMessage({
                      id: 'rule.module.text.rule.describe',
                    })}
                    &nbsp;: {record?.ruleDesc || '-'}
                  </div>
                </div>
              }
              style={{
                fontWeight: 500,
                color: 'rgb(58, 58, 58)',
              }}
            />
            <Disposition
              placement={'topLeft'}
              maxWidth={breakpoints?.xxl ? 600 : 400}
              rows={1}
              text={record?.ruleTypeNameList?.toString() || '-'}
              style={{
                color: 'rgb(166, 167, 167)',
                fontSize: 13,
              }}
            />
          </div>
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.asset.type',
      }),
      dataIndex: 'resourceTypeStr',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record: API.RuleProjectInfo) => {
        return <ThemeTag text={record?.resourceTypeStr || '-'} />;
      },
    },
    {
      title: intl.formatMessage({
        id: 'home.module.inform.columns.riskLevel',
      }),
      dataIndex: 'riskLevel',
      valueType: 'select',
      valueEnum: valueListAsValueEnum(RiskLevelList),
      align: 'center',
      hideInSearch: true,
      render: (_, record: API.RuleProjectInfo) => {
        return obtainRiskLevel(RiskLevelList, record?.riskLevel as string);
      },
    },
    {
      title: intl.formatMessage({
        id: 'common.table.columns.platform',
      }),
      dataIndex: 'platform',
      valueType: 'select',
      valueEnum: valueListAsValueEnum(platformList),
      align: 'center',
      hideInSearch: true,
      render: (_, record) => {
        return obtainPlatformEasyIcon(record.platform!, platformList);
      },
      fieldProps: {
        onChange: (value: any) => {
          formActionRef.current?.setFieldValue('resourceTypeList', null);
          setResourceTypeList([]);
          requestResourceTypeList(value);
        },
      },
    },
    {
      title: intl.formatMessage({
        id: 'asset.module.risk.number',
      }),
      dataIndex: 'riskCount',
      valueType: 'text',
      hideInSearch: true,
      align: 'center',
      sorter: true,
      render: (_, record) => (
        <Button
          type={'link'}
          size={'small'}
          href={`/riskManagement/riskList?platform=${record?.platform}&ruleCode=${record?.ruleCode} `}
        >
          {record?.riskCount}
        </Button>
      ),
    },
    {
      title: intl.formatMessage({
        id: 'rule.table.columns.text.isRunning',
      }),
      dataIndex: 'isRunning',
      valueType: 'text',
      hideInSearch: true,
      align: 'center',
      render: (_, record) => {
        const color = record?.isRunning ? 'green' : 'gray';
        const status = record?.isRunning ? 'running' : 'stop';
        return (
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <Tooltip title={status}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: color, cursor: 'pointer' }} />
            </Tooltip>
          </div>
        );
      }
    },
    {
      title: intl.formatMessage({
        id: 'rule.input.text.rule.group.creator',
      }),
      dataIndex: 'username',
      valueType: 'text',
      hideInSearch: true,
      width: 120,
    },
    {
      title: intl.formatMessage({
        id: 'common.table.columns.last.scan.time',
      }),
      dataIndex: 'lastScanTime',
      valueType: 'dateTime',
      hideInSearch: true,
      align: 'left',
      width: 160,
    },
    {
      title: intl.formatMessage({
        id: 'layout.routes.title.ruleGroup',
      }),
      dataIndex: 'groupName',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      width: 240,
      render: (_, record: API.RuleProjectInfo) => {
        return (
          <Disposition
            placement={'topLeft'}
            maxWidth={220}
            rows={2}
            text={record?.ruleGroupNameList?.toString() || '-'}
            style={{
              color: 'rgb(51, 51, 51)',
            }}
          />
        );
      },
    },
    {
      title: intl.formatMessage({
        id: 'common.table.columns.createAndUpdateTime',
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
        id: 'common.table.columns.rule.status',
      }),
      dataIndex: 'status',
      hideInTable: true,
      valueEnum: {
        valid: intl.formatMessage({
          id: 'common.button.text.enable',
        }),
        invalid: intl.formatMessage({
          id: 'common.button.text.disable',
        }),
      },
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.cloud.operate',
      }),
      dataIndex: 'option',
      valueType: 'option',
      align: 'center',
      fixed: 'right',
      render: (_, record: API.RuleProjectInfo) => (
        <Space size={'small'}>
          <Button
            size={'small'}
            onClick={() => setActiveRow(record.id)}
            type="link"
            target={'_self'}
            href={`/ruleManagement/ruleProject/edit?id=${record?.id}`}
          >
            <Tooltip
              title={intl.formatMessage({
                id: 'common.button.text.edit',
              })}
            >
              <EditOutlined />
            </Tooltip>
          </Button>

          <Popover
            content={
              <Space>
                <Popconfirm
                  title={intl.formatMessage({
                    id: 'common.button.text.delete.confirm',
                  })}
                  onConfirm={() => onClickDelRule(record.id!)}
                  okText={intl.formatMessage({
                    id: 'common.button.text.ok',
                  })}
                  cancelText={intl.formatMessage({
                    id: 'common.button.text.cancel',
                  })}
                >
                  <Button block type="link" danger size={'small'}>
                    {intl.formatMessage({
                      id: 'common.button.text.delete',
                    })}
                  </Button>
                </Popconfirm>

                <Button
                  block
                  loading={scanLoading[Number(record.id)]}
                  onClick={() => onClickScanByRule(record.id!)}
                  type="link"
                  target={'_blank'}
                  size={'small'}
                >
                  {intl.formatMessage({
                    id: 'common.button.text.test',
                  })}
                </Button>

                <Button
                  block
                  loading={copyLoading[Number(record.id)]}
                  onClick={() => onClickCopyByRule(record.id!)}
                  type="link"
                  target={'_blank'}
                  size={'small'}
                >
                  {intl.formatMessage({
                    id: 'common.button.text.copy',
                  })}
                </Button>
              </Space>
            }
          >
            <Button type={'link'} icon={<MoreOutlined />} />
          </Popover>

          <Tooltip
            title={intl.formatMessage({
              id: 'rule.module.text.tooltip.status',
            })}
          >
            <Switch
              checkedChildren={intl.formatMessage({
                id: 'common.button.text.enable',
              })}
              unCheckedChildren={intl.formatMessage({
                id: 'common.button.text.disable',
              })}
              checked={record?.status === 'valid'}
              onClick={() =>
                onClickChangeRuleStatus(
                  record.id!,
                  record?.status === 'valid' ? 'invalid' : 'valid',
                )
              }
            />
          </Tooltip>
        </Space>
      ),
    },
  ];

  return (
    <PageContainer
      ghost
      title={false}
      className={styles['rulePageContainer']}
      breadcrumbRender={false}
    >
      {contextHolder}
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
                <Checkbox.Group options={valueListAddTag(RiskLevelList)} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item
                name="ruleCodeList"
                label={intl.formatMessage({
                  id: 'home.module.inform.columns.ruleName',
                })}
                style={{ marginBottom: 0 }}
              >
                <Select
                  // @ts-ignore
                  filterOption={filterOption}
                  placeholder={intl.formatMessage({
                    id: 'common.select.text.placeholder',
                  })}
                  allowClear
                  options={allRuleList}
                  mode={'multiple'}
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
                name="ruleGroupIdList"
                label={intl.formatMessage({
                  id: 'layout.routes.title.ruleGroup',
                })}
                style={{ marginBottom: 0, width: '100%' }}
              >
                <Select
                  placeholder={intl.formatMessage({
                    id: 'common.select.text.placeholder',
                  })}
                  options={ruleGroupList}
                  allowClear
                  mode={'multiple'}
                />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item
                name="ruleTypeIdList"
                label={intl.formatMessage({
                  id: 'home.module.inform.columns.ruleTypeName',
                })}
                style={{ marginBottom: 0, width: '100%' }}
              >
                <Cascader
                  placeholder={intl.formatMessage({
                    id: 'common.select.text.placeholder',
                  })}
                  showCheckedStrategy={SHOW_CHILD}
                  allowClear
                  showSearch
                  fieldNames={{
                    label: 'typeName',
                    value: 'id',
                    children: 'childList',
                  }}
                  multiple
                  options={ruleTypeList || []}
                />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </ProCard>
      <ProTable<API.RuleProjectInfo>
        scroll={{ x: 'max-content' }}
        rowSelection={{
          type: 'checkbox',
          selectedRowKeys: selectedRowKeys,
          onChange: (selectedRowKeys) => setSelectedRowKeys(selectedRowKeys),
          preserveSelectedRowKeys: true
        }}
        headerTitle={
          <div className={styleType['customTitle']}>
            <Space>
              {intl.formatMessage({
                id: 'rule.module.text.rule.inquiry',
              })}
            </Space>
          </div>
        }
        actionRef={tableActionRef}
        formRef={formActionRef}
        rowClassName={activeRowType}
        rowKey="id"
        search={{
          span: 6,
          defaultCollapsed: false, // Default Expand
          collapseRender: false, // Hide expand/close button
          labelWidth: 0,
        }}
        toolBarRender={() => [
          <Popover
            key="SYNC"
            open={popoverVisible}
            onOpenChange={(visible) => setPopoverVisible(visible)}
            title={intl.formatMessage({
              id: 'rule.module.text.sync.confirm',
            })}
            content={
              <Space>
                <Button
                  danger
                  type="primary"
                  loading={syncLoading}
                  onClick={async () => {
                    setSyncLoading(true);
                    const hide = messageApi.loading(intl.formatMessage({
                      id: 'rule.module.text.sync.loading',
                    }));
                    try {
                      const res = await loadRuleFromGithub({ coverage: true });
                      if (res.code === 200 || res.msg === 'success') {
                        messageApi.success(intl.formatMessage({
                          id: 'rule.module.text.sync.success',
                        }));
                        tableActionRef.current?.reloadAndRest?.();
                      }
                    } finally {
                      hide();
                      setSyncLoading(false);
                      setPopoverVisible(false);
                    }
                  }}
                >
                  {intl.formatMessage({
                    id: 'rule.module.text.sync.overwrite',
                  })}
                </Button>
                <Button
                  type="primary"
                  loading={syncLoading}
                  onClick={async () => {
                    setSyncLoading(true);
                    const hide = messageApi.loading(intl.formatMessage({
                      id: 'rule.module.text.sync.loading',
                    }));
                    try {
                      const res = await loadRuleFromGithub({ coverage: false });
                      if (res.code === 200 || res.msg === 'success') {
                        messageApi.success(intl.formatMessage({
                          id: 'rule.module.text.sync.success',
                        }));
                        tableActionRef.current?.reloadAndRest?.();
                      }
                    } finally {
                      hide();
                      setSyncLoading(false);
                      setPopoverVisible(false);
                    }
                  }}
                >
                  {intl.formatMessage({
                    id: 'rule.module.text.sync.no.overwrite',
                  })}
                </Button>
                <Button
                  onClick={() => {
                    setPopoverVisible(false);
                  }}
                >
                  {intl.formatMessage({
                    id: 'common.button.text.cancel',
                  })}
                </Button>
                </Space>
            }
            trigger="click"
          >
            <Button type="primary">
              {intl.formatMessage({
                id: 'rule.module.text.sync.button',
              })}
            </Button>
          </Popover>,
          <Button
            key="CREATE"
            type="primary"
            href={'/ruleManagement/ruleProject/edit'}
          >
            {intl.formatMessage({
              id: 'rule.extend.basic.add',
            })}
          </Button>,
          <Button
            loading={exportLoading}
            key="EXPORT"
            type="primary"
            onClick={() => onClickExportRuleList(selectedRowKeys)}
          >
            {intl.formatMessage({
              id: 'common.button.text.export',
            })}
          </Button>,
        ]}
        request={async (
          params: Record<string, any>,
          sort: Record<string, any>,
        ) => {
          const { pageSize, current, ...reset } = params;
          const filterForm = form.getFieldsValue();
          // When there is field sorting
          const sorter = obtainFirstProperty(sort);
          const postBody: Record<string, any> = {
            ...reset,
            ...filterForm,
            page: current,
            size: pageSize,
          };
          if (!isEmpty(sorter)) {
            postBody.sortParam = sorter?.key;
            postBody.sortType = sorter?.value?.slice(0, -3)?.toUpperCase();
          }
          const { content, code } = await queryRuleList(postBody);
          return {
            data: content?.data || [],
            total: content?.total || 0,
            success: code === 200 || false,
          };
        }}
        onReset={(): void => {
          form.resetFields();
          setSelectedRowKeys([]);
          // @ts-ignore
          tableActionRef.current?.reloadAndRest();
        }}
        columns={columns}
        columnsState={{
          defaultValue: columnsStateMap,
          persistenceType: 'localStorage',
          persistenceKey: 'RULE_TABLE_LIST_CACHE',
        }}
        pagination={{
          showQuickJumper: false,
          showSizeChanger: true,
          defaultPageSize: 10,
          defaultCurrent: 1,
        }}
        expandable={{
          expandedRowRender: (record) => (
            <Row>
              <Col
                span={3}
                className={styles['dimBlock']}
                style={{
                  borderLeft: '0.5px solid rgb(239, 239, 239)',
                  borderBottom: 'none',
                }}
              >
                {intl.formatMessage({
                  id: 'home.module.inform.columns.ruleName',
                })}
              </Col>
              <Col
                span={9}
                className={styles['cleanBlock']}
                style={{ borderBottom: 'none' }}
              >
                {record?.ruleName || '-'}
              </Col>
              <Col
                span={3}
                className={styles['dimBlock']}
                style={{ borderBottom: 'none' }}
              >
                {intl.formatMessage({
                  id: 'rule.module.text.rule.describe',
                })}
              </Col>
              <Col
                span={9}
                className={styles['cleanBlock']}
                style={{ borderBottom: 'none' }}
              >
                {record?.ruleDesc || '-'}
              </Col>
              <Col
                span={3}
                className={styles['dimBlock']}
                style={{ borderLeft: '0.5px solid rgb(239, 239, 239)' }}
              >
                {intl.formatMessage({
                  id: 'rule.module.text.repair.suggestions',
                })}
              </Col>
              <Col
                span={5}
                className={styles['cleanBlock']}
                style={{ flexDirection: 'column' }}
              >
                <div>{record?.advice || '-'}</div>
              </Col>
              <Col span={3} className={styles['dimBlock']}>
                {intl.formatMessage({
                  id: 'rule.module.text.reference.link',
                })}
              </Col>
              <Col span={5} className={styles['cleanBlock']}>
                <a
                  type={'link'}
                  href={record?.link}
                  target={'_blank'}
                  rel="noreferrer"
                  className={styles['lineBreak']}
                >
                  {record?.link || '-'}
                </a>
              </Col>
              <Col span={3} className={styles['dimBlock']}>
                {intl.formatMessage({
                  id: 'rule.module.text.risk.context.template',
                })}
              </Col>
              <Col span={5} className={styles['cleanBlock']}>
                {record?.context || '-'}
              </Col>
            </Row>
          ),
          columnTitle: <div style={{ width: 30, textAlign: 'center' }} />,
          columnWidth: 30,
          rowExpandable: (): boolean => true,
          expandIcon: ({ expanded, onExpand, record }) =>
            expanded ? (
              <DownCircleOutlined
                style={{ color: '#457aff', fontSize: 14 }}
                onClick={(e) => onExpand(record, e)}
              />
            ) : (
              <RightCircleOutlined
                style={{ color: '#457aff', fontSize: 14 }}
                onClick={(e) => onExpand(record, e)}
              />
            ),
        }}
      />

      <EditModalForm
        editFormVisible={editFormVisible}
        setEditFormVisible={setEditFormVisible}
        groupInfo={projectInfoRef.current}
        tableActionRef={tableActionRef}
      />
    </PageContainer>
  );
};

export default RuleProject;

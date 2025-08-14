import ThemeTag from '@/components/Common/ThemeTag';
import styleType from '@/components/Common/index.less';
import Disposition from '@/components/Disposition';
import DispositionPro from '@/components/DispositionPro';
import { RiskLevelList } from '@/utils/const';
import {
  obtainFirstProperty,
  obtainPlatformEasyIcon,
  obtainRiskLevel,
  valueListAsValueEnum,
} from '@/utils/shared';
import {
  MinusOutlined,
  PlayCircleOutlined,
  PlayCircleFilled,
  PauseCircleFilled,
  InfoCircleOutlined,
  StarFilled,
} from '@ant-design/icons';
import {
  ActionType,
  ProColumns,
  ProFormInstance,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl, useModel } from '@umijs/max';
import {
  Breakpoint,
  Button,
  Form,
  Grid,
  message,
  Popconfirm,
  Radio,
  Space,
  Tooltip,
} from 'antd';
import { MessageType } from 'antd/es/message/interface';
import { isEmpty } from 'lodash';
import React, { useRef, useState, useEffect } from 'react';
import { queryEffectRuleList, removeTenantSelectRule, scanByRule, scanRuleList, batchDeleteTenantSelectRule } from '@/services/rule/RuleController';
import { createTableRowConfig } from '../utils/tableRowUtils';
import RuleDetailDrawer from './RuleDetailDrawer';

const { useBreakpoint } = Grid;

interface SelectedRulesProps {
  form: any;
  platformList: any;
  resourceTypeList: any[];
  ruleGroupList: any;
  ruleTypeList: any;
  allRuleList: any;
  queryTrigger?: number;
}

const SelectedRules: React.FC<SelectedRulesProps> = ({
                                                       form,
                                                       platformList,
                                                       resourceTypeList,
                                                       ruleGroupList,
                                                       ruleTypeList,
                                                       allRuleList,
                                                       queryTrigger,
                                                     }) => {
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Ant Design Provide monitoring of screen width changes
  const breakpoints: Partial<Record<Breakpoint, boolean>> = useBreakpoint();
  // Table Action
  const tableActionRef = useRef<ActionType>();
  // Form Action
  const formActionRef = useRef<ProFormInstance>();
  // Intl API
  const intl = useIntl();
  // Select status Table Row
  const [activeRow, setActiveRow] = useState<number>();
  // Scanning Loading
  const [scanLoading, setScanLoading] = useState<any>({});
  // Detection Loading
  const [detectLoading, setDetectLoading] = useState<any>({});
  // Remove Loading
  const [removeLoading, setRemoveLoading] = useState<any>({});
  // Selected Row Keys
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  // Batch Scan Loading
  const [batchScanLoading, setBatchScanLoading] = useState<boolean>(false);
  // Batch Remove Loading
  const [batchRemoveLoading, setBatchRemoveLoading] = useState<boolean>(false);
  // Rule Detail Drawer
  const [ruleDetailVisible, setRuleDetailVisible] = useState<boolean>(false);
  const [selectedRuleId, setSelectedRuleId] = useState<number>();
  // Data status for empty state message
  const [hasData, setHasData] = useState<boolean>(true);
  const [dataLoaded, setDataLoaded] = useState<boolean>(false);
  // Rule type selection state (selected: 租户自选, default: 默认规则, all: 全部)
  const [ruleType, setRuleType] = useState<'selected' | 'default' | 'all'>('all');

  // Current activation item Row
  const activeRowType = (record: Record<string, any>): string => {
    return record.id === activeRow ? 'ant-table-row-selected' : '';
  };

  // Handle row click to show rule detail drawer
  const handleRowClick = (record: any): void => {
    setSelectedRuleId(record.id);
    setRuleDetailVisible(true);
  };

  useEffect(() => {
    if (queryTrigger !== undefined && queryTrigger > 0) {
      tableActionRef.current?.reload();
    }
  }, [queryTrigger]);

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

  // Remove from selected
  const onClickRemoveFromSelected = async (record: any): Promise<void> => {
    const id = record.id;
    setRemoveLoading({ ...removeLoading, [id]: true });

    try {
      const result = await removeTenantSelectRule({ ruleCode: record.ruleCode });

      if (result.code === 200 || result.msg === 'success') {
        messageApi.success(intl.formatMessage({ id: 'common.message.text.success' }));
        tableActionRef.current?.reloadAndRest?.();
      }
    } catch (error) {
      messageApi.error(intl.formatMessage({ id: 'common.message.text.fail' }));
    } finally {
      setRemoveLoading({ ...removeLoading, [id]: false });
    }
  };

  // Batch scan rules
  const onClickBatchScan = async (): Promise<void> => {
    if (selectedRowKeys.length === 0) {
      return;
    }

    setBatchScanLoading(true);

    try {
      const idList = selectedRowKeys.map(key => Number(key));
      const result = await scanRuleList({ idList });

      if (result.code === 200 || result.msg === 'success') {
        messageApi.success(intl.formatMessage({ id: 'common.message.text.success' }));
        setSelectedRowKeys([]);
        tableActionRef.current?.reloadAndRest?.();
      }
    } catch (error) {
      messageApi.error(intl.formatMessage({ id: 'common.message.text.fail' }));
    } finally {
      setBatchScanLoading(false);
    }
  };

  // Batch remove from selected
  const onClickBatchRemove = async (): Promise<void> => {
    if (selectedRowKeys.length === 0) {
      return;
    }

    setBatchRemoveLoading(true);

    try {
      const formValues = form.getFieldsValue();
      const requestParams: API.ListRuleRequest = {
        page: 1,
        size: 1000,
        platformList: formValues.platformList,
        riskLevelList: formValues.riskLevelList,
        ruleCodeList: formValues.ruleCodeList,
        resourceTypeList: formValues.resourceTypeList,
        ruleGroupIdList: formValues.ruleGroupIdList,
        ruleTypeIdList: formValues.ruleTypeIdList,
      };

      const response = await queryEffectRuleList(requestParams);
      const allData = response?.content?.data || [];
      const selectedData = allData.filter((item: any) => selectedRowKeys.includes(item.id));
      const ruleCodeList = selectedData.map((item: any) => item.ruleCode);


      const result = await batchDeleteTenantSelectRule({ ruleCodeList });

      if (result.code === 200 || result.msg === 'success') {
        messageApi.success(intl.formatMessage({ id: 'common.message.text.success' }));
        setSelectedRowKeys([]);
        tableActionRef.current?.reloadAndRest?.();
      }
    } catch (error) {
      messageApi.error(intl.formatMessage({ id: 'common.message.text.fail' }));
    } finally {
      setBatchRemoveLoading(false);
    }
  };

  // Request selected rules data
  const requestSelectedRulesData = async (
    params: Record<string, any>,
    sort: Record<string, any>,
  ) => {
    const { pageSize, current, ...searchParams } = params;

    try {
      const formValues = form.getFieldsValue();

      const requestParams: API.ListRuleRequest & { effectRuleType?: string } = {
        page: current || 1,
        size: pageSize || 10,
        platformList: formValues.platformList,
        riskLevelList: formValues.riskLevelList,
        ruleCodeList: formValues.ruleCodeList,
        resourceTypeList: formValues.resourceTypeList,
        ruleGroupIdList: formValues.ruleGroupIdList,
        ruleTypeIdList: formValues.ruleTypeIdList,
        effectRuleType: ruleType,
        ...searchParams,
      };

      if (sort && Object.keys(sort).length > 0) {
        const sortKey = Object.keys(sort)[0];
        const sortOrder = sort[sortKey];
        requestParams.sortParam = sortKey;
        requestParams.sortType = sortOrder === 'ascend' ? 'ASC' : 'DESC';
      }

      const response = await queryEffectRuleList(requestParams);

      if (response?.content) {
        const data = response.content.data || [];
        const total = response.content.total || 0;
        
        setHasData(total > 0);
        setDataLoaded(true);
        
        return {
          data,
          total,
          success: true,
        };
      } else {
        setHasData(false);
        setDataLoaded(true);
        return {
          data: [],
          total: 0,
          success: false,
        };
      }
    } catch (error) {
      setHasData(false);
      setDataLoaded(true);
      return {
        data: [],
        total: 0,
        success: false,
      };
    }
  };

  const columns: ProColumns<any, 'text'>[] = [
    {
      title: intl.formatMessage({
        id: 'home.module.inform.columns.ruleName',
      }),
      dataIndex: 'ruleName',
      valueType: 'text',
      align: 'left',
      hideInSearch: true,
      render: (_, record) => {
        return (
          <div>
            <div
              style={{
                fontWeight: 500,
                color: 'rgb(58, 58, 58)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <span>{record?.ruleName || '-'}</span>
              {record?.defaultRuleSelected && (
                <Tooltip title="default">
                  <StarFilled style={{ color: '#faad14', fontSize: '14px' }} />
                </Tooltip>
              )}
            </div>
            <div
              style={{
                color: 'rgb(166, 167, 167)',
                fontSize: 13,
              }}
            >
              {record?.ruleTypeNameList?.toString() || '-'}
            </div>
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
      render: (_, record) => {
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
      render: (_, record) => {
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
          href={`/riskManagement/riskList?platform=${record?.platform}&ruleCode=${record?.ruleCode}`}
        >
          {record?.riskCount}
        </Button>
      ),
    },

    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.lastScanTime',
      }),
      dataIndex: 'lastScanTime',
      valueType: 'text',
      hideInSearch: true,
      align: 'center',
      width: 150,
      sorter: true,
      render: (_, record) => {
        if (record?.lastScanTime) {
          return (
            <Tooltip title={record.lastScanTime}>
              <span>{record.lastScanTime}</span>
            </Tooltip>
          );
        }
        return '-';
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
      width: 180,
      render: (_, record) => {
         const isRunning = record?.isRunning;
         const canDetect = isRunning === 0;
         
         const getButtonIcon = () => {
           if (isRunning === 1) {
             return <PlayCircleFilled />;
           } else {
             return <PlayCircleOutlined />;
           }
         };

         return (
           <Space size={'small'}>
             <Button
               block
               loading={scanLoading[Number(record.id)]}
               disabled={!canDetect}
               onClick={(e) => {
                 e.stopPropagation();
                 onClickScanByRule(record.id!);
               }}
               type="default"
               target={'_blank'}
               size={'small'}
               icon={getButtonIcon()}
               style={{
                 color: isRunning === 1 ? '#52c41a' : undefined,
                 borderColor: isRunning === 1 ? '#52c41a' : undefined
               }}
             >
               {intl.formatMessage({
                 id: isRunning === 1 ? 'common.button.text.running' : 'common.button.text.test',
               })}
             </Button>

             {ruleType === 'selected' && (
               <Popconfirm
                  title={intl.formatMessage({
                    id: 'rule.module.selected.rules.popconfirm.content',
                  })}
                  onConfirm={(e) => {
                    e?.stopPropagation();
                    onClickRemoveFromSelected(record);
                  }}
                  onCancel={(e) => e?.stopPropagation()}
                  okText={intl.formatMessage({
                    id: 'common.button.text.ok',
                  })}
                  cancelText={intl.formatMessage({
                    id: 'common.button.text.cancel',
                  })}
                >
                 <Button
                   danger
                   size="small"
                   loading={removeLoading[Number(record.id)]}
                   disabled={isRunning === 1}
                   icon={<MinusOutlined />}
                   onClick={(e) => e.stopPropagation()}
                 >

                 </Button>
               </Popconfirm>
             )}
           </Space>
         );
       },
    },
  ];

  return (
    <>
      {contextHolder}
      <ProTable<any>
        scroll={{ x: 'max-content' }}
        rowSelection={{
          type: 'checkbox',
          selectedRowKeys: selectedRowKeys,
          onChange: (selectedRowKeys) => setSelectedRowKeys(selectedRowKeys),
          preserveSelectedRowKeys: true,
        }}
        headerTitle={
          <div className={styleType['customTitle']}>
            <Space>
              <Radio.Group
                value={ruleType}
                onChange={(e) => {
                  setRuleType(e.target.value);
                  setSelectedRowKeys([]);
                  tableActionRef.current?.reload();
                }}
                size="middle"
                buttonStyle="solid"
              >
                <Radio.Button value="all">{intl.formatMessage({
                  id: 'common.module.text.all',
                })}</Radio.Button>
                <Radio.Button value="selected">{intl.formatMessage({
                  id: 'common.module.text.selected',
                })}</Radio.Button>
                <Radio.Button value="default">{intl.formatMessage({
                  id: 'common.module.text.default',
                })}</Radio.Button>
              </Radio.Group>
            </Space>
          </div>
        }
        actionRef={tableActionRef}
        formRef={formActionRef}
        rowClassName={activeRowType}
        rowKey="id"
        search={false}
        toolBarRender={() => [
          <Button
            key="BATCH_DETECT"
            type="primary"
            loading={batchScanLoading}
            disabled={selectedRowKeys.length === 0}
            onClick={onClickBatchScan}
          >
            {intl.formatMessage({
              id: 'rule.module.text.batch.test',
            })}
          </Button>,
          ruleType === 'selected' && (
             <Button
               key="BATCH_REMOVE"
               danger
               loading={batchRemoveLoading}
               disabled={selectedRowKeys.length === 0}
               onClick={onClickBatchRemove}
             >
               {intl.formatMessage({
                 id: 'rule.module.text.batch.remove',
               })}
             </Button>
           ),
        ].filter(Boolean)}
        request={requestSelectedRulesData}
        columns={columns}
        pagination={{
          showQuickJumper: false,
          showSizeChanger: true,
          defaultPageSize: 10,
          defaultCurrent: 1,
        }}
        onRow={createTableRowConfig(handleRowClick)}
      />
      <RuleDetailDrawer
        visible={ruleDetailVisible}
        onClose={() => setRuleDetailVisible(false)}
        ruleId={selectedRuleId}
      />
    </>
  );
};

export default SelectedRules;
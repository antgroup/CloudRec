import ThemeTag from '@/components/Common/ThemeTag';
import styleType from '@/components/Common/index.less';
import Disposition from '@/components/Disposition';
import DispositionPro from '@/components/DispositionPro';
import { queryGroupTypeList } from '@/services/resource/ResourceController';
import {
  copyRule,
  deleteRule,
  queryRuleList,
  scanByRule,
  loadRuleFromGithub,
  queryExportRuleList,
  changeRuleStatus,
  addTenantSelectRule,
  removeTenantSelectRule,
  batchAddTenantSelectRule,
} from '@/services/rule/RuleController';
import RuleDetailDrawer from './RuleDetailDrawer';
import { RiskLevelList } from '@/utils/const';
import {
  BlobExportZIPFn,
  obtainFirstProperty,
  obtainPlatformEasyIcon,
  obtainRiskLevel,
  valueListAsValueEnum,
} from '@/utils/shared';
import {
  DownOutlined,
  EditOutlined,
  ExportOutlined,
  MoreOutlined,
  PlusOutlined,
  MinusOutlined,
  SyncOutlined,
  TeamOutlined,
} from '@ant-design/icons';
import {
  ActionType,
  ProColumns,
  ProFormInstance,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl, useModel, useRequest } from '@umijs/max';
import {
  Badge,
  Breakpoint,
  Button,
  Dropdown,
  Form,
  Grid,
  message,
  Popconfirm,
  Popover,
  Space,
  Switch,
  Tooltip,
} from 'antd';
import { MessageType } from 'antd/es/message/interface';
import { isEmpty } from 'lodash';
import React, { useRef, useState, useEffect } from 'react';
import { createTableRowConfig } from '../utils/tableRowUtils';

const { useBreakpoint } = Grid;

interface RuleMarketProps {
  form: any;
  platformList: any;
  resourceTypeList: any[];
  ruleGroupList: any;
  ruleTypeList: any;
  allRuleList: any;
  checkNewRules: () => Promise<void>;
  newRulesCount: number;
  queryTrigger?: number;
}

const RuleMarket: React.FC<RuleMarketProps> = ({
  form,
  platformList,
  resourceTypeList,
  ruleGroupList,
  ruleTypeList,
  allRuleList,
  checkNewRules,
  newRulesCount,
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
  // Rule Detail Drawer
  const [ruleDetailVisible, setRuleDetailVisible] = useState(false);
  const [selectedRuleId, setSelectedRuleId] = useState<number>();
  // Copy Loading
  const [copyLoading, setCopyLoading] = useState<any>({});
  // Add to Selected Loading
  const [addLoading, setAddLoading] = useState<any>({});
  // Remove from Selected Loading
  const [removeLoading, setRemoveLoading] = useState<any>({});
  // Selected Row Keys
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  // Sync Rules Popover Visible
  const [popoverVisible, setPopoverVisible] = useState<boolean>(false);
  // Sync Rules Loading Status
  const [syncLoading, setSyncLoading] = useState<boolean>(false);
  // Export Loading
  const [exportLoading, setExportLoading] = useState<boolean>(false);
  // Batch Add to Selected Loading
  const [batchAddLoading, setBatchAddLoading] = useState<boolean>(false);

  useEffect(() => {
    if (queryTrigger !== undefined && queryTrigger > 0) {
      tableActionRef.current?.reload();
    }
  }, [queryTrigger]);

  // Current activation item Row
  const activeRowType = (record: Record<string, any>): string => {
    return record.id === activeRow ? 'ant-table-row-selected' : '';
  };

  const handleRowClick = (record: API.RuleProjectInfo) => {
    setSelectedRuleId(record.id);
    setRuleDetailVisible(true);
  };

  const handleCloseRuleDetail = () => {
    setRuleDetailVisible(false);
    setSelectedRuleId(undefined);
  };

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

  // Add to Selected Rules
  const onClickAddToSelected = async (record: API.RuleProjectInfo): Promise<void> => {
    const id = record.id!;
    setAddLoading({ ...addLoading, [id]: true });
    
    try {
      const result = await addTenantSelectRule({ ruleCode: record.ruleCode! });
      
      if (result.code === 200 || result.msg === 'success') {
        messageApi.success(intl.formatMessage({ id: 'common.message.text.success' }));
        tableActionRef.current?.reloadAndRest?.();
      } 
    } catch (error) {
      messageApi.error(intl.formatMessage({ id: 'common.message.text.failed' }));
    } finally {
      setAddLoading({ ...addLoading, [id]: false });
    }
  };

  // Remove from Selected Rules
  const onClickRemoveFromSelected = async (record: API.RuleProjectInfo): Promise<void> => {
    const id = record.id!;
    setRemoveLoading({ ...removeLoading, [id]: true });
    
    try {
      const result = await removeTenantSelectRule({ ruleCode: record.ruleCode! });
      
      if (result.code === 200 || result.msg === 'success') {
        messageApi.success(intl.formatMessage({ id: 'common.message.text.success' }));
        tableActionRef.current?.reloadAndRest?.();
      } 
    } catch (error) {
      messageApi.error(intl.formatMessage({ id: 'common.message.text.failed' }));
    } finally {
      setRemoveLoading({ ...removeLoading, [id]: false });
    }
  };

  /**
   * Batch add selected rules to tenant
   * @param selectedRowKeys - Array of selected rule IDs
   */
  const onClickBatchAddToSelected = async (): Promise<void> => {
    setBatchAddLoading(true);
    try {
      // Get rule codes from selected rows
      const selectedRules = allRuleList?.filter((rule: API.RuleProjectInfo) => 
        selectedRowKeys.includes(rule.id!)
      );
      const ruleCodeList = selectedRules?.map((rule: API.RuleProjectInfo) => rule.ruleCode!) || [];

      if (ruleCodeList.length === 0) {
        messageApi.warning(intl.formatMessage({ id: 'common.message.text.no.valid.data' }));
        return;
      }

      const result = await batchAddTenantSelectRule({ ruleCodeList });
      
      if (result.code === 200 || result.msg === 'success') {
        messageApi.success(intl.formatMessage({ id: 'common.message.text.success' }));
        tableActionRef.current?.reloadAndRest?.();
        setSelectedRowKeys([]);
      }
    } catch (error) {
      messageApi.error(intl.formatMessage({ id: 'common.message.text.failed' }));
    } finally {
      setBatchAddLoading(false);
    }
  };

  // Export Rule List
  const onClickExportRuleList = (selectedRowKeys?: React.Key[]) => {
    setExportLoading(true);

    queryExportRuleList(
      selectedRowKeys ? { idList: selectedRowKeys } as any : undefined,
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
        const isInUse = record?.selectedTenantNameList && record.selectedTenantNameList.length > 0;
        
        return (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <DispositionPro
                placement={'topLeft'}
                maxWidth={breakpoints?.xxl ? 600 : 400}
                rows={1}
                text={record?.ruleName || '-'}
                style={{
                  fontWeight: 500,
                  color: 'rgb(58, 58, 58)',
                }}
              />
              {isInUse && (
                <Tooltip
                  title={
                    <div>
                      {record.selectedTenantNameList?.map((tenantName, index) => (
                        <div key={index} style={{ fontSize: 12 }}>
                          • {tenantName}
                        </div>
                      ))}
                    </div>
                  }
                  placement="topRight"
                >
                  <TeamOutlined 
                    style={{ 
                      color: '#1890ff', 
                      fontSize: 14,
                      cursor: 'pointer'
                    }} 
                  />
                </Tooltip>
              )}
            </div>
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
        id: 'rule.input.text.rule.group.creator',
      }),
      dataIndex: 'username',
      valueType: 'text',
      hideInSearch: true,
      width: 120,
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
            onClick={(e) => {
              e.stopPropagation();
              setActiveRow(record.id);
            }}
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
                  onConfirm={(e) => {
                    e?.stopPropagation();
                    onClickDelRule(record.id!);
                  }}
                  okText={intl.formatMessage({
                    id: 'common.button.text.ok',
                  })}
                  cancelText={intl.formatMessage({
                    id: 'common.button.text.cancel',
                  })}
                >
                  <Button 
                    block 
                    type="link" 
                    danger 
                    size={'small'}
                    onClick={(e) => e.stopPropagation()}
                  >
                    {intl.formatMessage({
                      id: 'common.button.text.delete',
                    })}
                  </Button>
                </Popconfirm>

                <Button
                  block
                  loading={copyLoading[Number(record.id)]}
                  onClick={(e) => {
                    e.stopPropagation();
                    onClickCopyByRule(record.id!);
                  }}
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
            <Button 
              type={'link'} 
              icon={<MoreOutlined />} 
              onClick={(e) => e.stopPropagation()}
            />
          </Popover>

          {record.tenantSelected ? (
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
                type="default"
                size="small"
                loading={removeLoading[Number(record.id)]}
                onClick={(e) => e.stopPropagation()}
                icon={<MinusOutlined />}
                danger
              >

              </Button>
            </Popconfirm>
          ) : (
            <Button
              type="primary"
              size="small"
              loading={addLoading[Number(record.id)]}
              onClick={(e) => {
                e.stopPropagation();
                onClickAddToSelected(record);
              }}
              icon={<PlusOutlined />}
            >

            </Button>
          )}

          <Tooltip
            title={intl.formatMessage({
              id: 'rule.module.text.tooltip.status',
            })}
          >
            <Switch
              checked={record?.status === 'valid'}
              onClick={(checked, e) => {
                e?.stopPropagation();
                onClickChangeRuleStatus(
                  record.id!,
                  record?.status === 'valid' ? 'invalid' : 'valid',
                );
              }}
            />
          </Tooltip>
        </Space>
      ),
    },
  ];

  return (
    <>
      {contextHolder}
      <ProTable<API.RuleProjectInfo>
        scroll={{ x: 'max-content' }}
        rowSelection={{
          type: 'checkbox',
          selectedRowKeys: selectedRowKeys,
          onChange: (selectedRowKeys) => setSelectedRowKeys(selectedRowKeys),
          preserveSelectedRowKeys: true,
        }}
        actionRef={tableActionRef}
        formRef={formActionRef}
        rowClassName={activeRowType}
        rowKey="id"
        search={false}
        toolBarRender={() => [
          <Button
            key="CREATE"
            type="primary"
            href={'/ruleManagement/ruleProject/edit'}
          >
            {intl.formatMessage({
              id: 'rule.extend.basic.add',
            })}
          </Button>,
          <Popover
            key="sync"
            open={popoverVisible}
            onOpenChange={(visible) => setPopoverVisible(visible)}
            title={intl.formatMessage({
              id: 'rule.module.text.sync.confirm',
            })}
            content={
              <Space>
                <Button
                  danger
                  type="default"
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
                        checkNewRules();
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
                  type="default"
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
                        checkNewRules();
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
            <div style={{ position: 'relative', display: 'inline-block' }}>
              <Button type="default">
                {intl.formatMessage({
                  id: 'rule.module.text.sync.button',
                })}
              </Button>
              {newRulesCount > 0 && (
                <div
                  style={{
                    position: 'absolute',
                    top: '-8px',
                    right: '-8px',
                    backgroundColor: '#ff4d4f',
                    color: 'white',
                    borderRadius: '50%',
                    width: '20px',
                    height: '20px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '12px',
                    fontWeight: 'bold',
                    zIndex: 1,
                  }}
                >
                  {newRulesCount > 99 ? '99+' : newRulesCount}
                </div>
              )}
            </div>
          </Popover>,
          <Button
            key="BATCH_ADD_TO_FAVORITES"
            type="default"
            loading={batchAddLoading}
            disabled={selectedRowKeys.length === 0}
            onClick={onClickBatchAddToSelected}
          >
            {intl.formatMessage({
              id: 'rule.module.text.batch.add.to.favorites',
            })}
          </Button>,
          <Button
            loading={exportLoading}
            key="EXPORT"
            type="default"
            disabled={selectedRowKeys.length === 0}
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
          onClose={handleCloseRuleDetail}
          ruleId={selectedRuleId}
        />
      </>
    );
  };

  export default RuleMarket;
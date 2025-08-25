import { useIntl, useSearchParams, useModel, history } from '@umijs/max';
import { PageContainer } from '@ant-design/pro-components';
import { Table, DatePicker, Space, Select, Form, Tag, Progress, Tooltip, Button, Modal, Typography, message } from 'antd';
import { CheckCircleOutlined, SyncOutlined, CloseCircleFilled, InfoCircleOutlined, CopyOutlined, FullscreenOutlined, FullscreenExitOutlined } from '@ant-design/icons';
import JSONEditor from '@/components/Editor/JSONEditor';
import { cloudAccountBaseInfoListV2 } from '@/services/account/AccountController';
import { obtainPlatformEasyIcon } from '@/utils/shared';
import { useEffect, useState } from 'react';
import { getCollectorRecordList, getErrorCodeList } from '@/services/account/AccountCollectorRecord';
import type { TablePaginationConfig } from 'antd/es/table';
import dayjs from 'dayjs';

const { RangePicker } = DatePicker;

const CollectionRecord = () => {
  const { platformList } = useModel('rule');
  const [form] = Form.useForm();
  const intl = useIntl();
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<API.CollectorRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [timeRange, setTimeRange] = useState<[dayjs.Dayjs | null, dayjs.Dayjs | null]>([dayjs().subtract(1, 'day'), dayjs().add(1,'day')]);
  const [selectedPlatform, setSelectedPlatform] = useState<string>(searchParams.get('platform') || '');
  const [selectedAccount, setSelectedAccount] = useState<string>('');
  const [accountOptions, setAccountOptions] = useState<{ label: string; value: string }[]>([]);
  const [errorCodeOptions, setErrorCodeOptions] = useState<{ label: string; value: string }[]>([]);
  const [selectedErrorCode, setSelectedErrorCode] = useState<string>();
  const [isFirstLoad, setIsFirstLoad] = useState(true);
  const [metadataModalVisible, setMetadataModalVisible] = useState(false);
  const [selectedMetadata, setSelectedMetadata] = useState<any>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);

  /**
   * Toggle fullscreen mode for metadata modal
   */
  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  /**
   * Handle modal close - reset fullscreen state
   */
  const handleModalClose = () => {
    setMetadataModalVisible(false);
    setIsFullscreen(false);
  };

  // query cloud account list
  const fetchAccountList = async (platform?: string, searchValue?: string) => {
    if (!platform) {
      setAccountOptions([]);
      return;
    }
    try {
      const res = await cloudAccountBaseInfoListV2({ platformList: [platform], cloudAccountSearch: searchValue });
      if (res.code === 200) {
        const options = res.content?.map((item: any) => ({
          label: item.alias,
          value: item.cloudAccountId,
        })) || [];
        setAccountOptions(options);
      }
    } catch (error) {
      console.error('Failed to obtain the list of cloud accounts:', error);
    }
  };

  useEffect(() => {
    if (selectedPlatform) {
      fetchAccountList(selectedPlatform);
    }
  }, [selectedPlatform]);

  // init cloud account list
  useEffect(() => {
    const platform = searchParams.get('platform');
    const cloudAccountId = searchParams.get('cloudAccountId');
    if (platform) {
      fetchAccountList(platform);
      if (cloudAccountId) {
        setSelectedAccount(cloudAccountId);
      }
    }
  }, []);

  const [current, setCurrent] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const fetchData = async () => {
    if (!selectedAccount && isFirstLoad) {
      setIsFirstLoad(false);
      return;
    }
    setLoading(true);
    setData([]);
    setTotal(0);
    try {
      const params: {
        startTimeArray: any[] | undefined;
        size: number;
        cloudAccountId: string;
        page: number;
        platform: string;
        errorCode?: string;
      } = {
        platform: selectedPlatform,
        cloudAccountId: selectedAccount,
        errorCode: selectedErrorCode,
        startTimeArray: timeRange[0] && timeRange[1] ?
          [timeRange[0].format('YYYY-MM-DD HH:mm:ss'), timeRange[1].format('YYYY-MM-DD HH:mm:ss')] :
          undefined,
        page: current,
        size: pageSize,
      };
      const res = await getCollectorRecordList(params);
      if (res.code === 200) {
        setData(res.content.data);
        setTotal(res.content.total);
      }
    } catch (error) {
      console.error('Failed to obtain the collection record list:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchErrorCodeList = async (platform?: string, cloudAccountId?: string) => {
    if (!platform) {
      setErrorCodeOptions([]);
      return;
    }
    try {
      const res = await getErrorCodeList({ platform, cloudAccountId });
      if (res) {
        const options = (res as any)?.content?.map((item: { description: string, count: number }) => ({
          label: `${item.description} (${item.count})`,
          value: item.description,
        })) || [];
        setErrorCodeOptions(options);
      }
    } catch (error) {
      console.error('Failed to obtain the list of error codes:', error);
    }
  };

  useEffect(() => {
    if (selectedPlatform) {
      fetchErrorCodeList(selectedPlatform, selectedAccount);
    }
  }, [selectedPlatform, selectedAccount]);

  const handleSearch = () => {
    setCurrent(1);
    fetchData();
  };

  useEffect(() => {
    fetchData();
  }, [current, pageSize, selectedPlatform, selectedAccount, selectedErrorCode, timeRange]);

  const columns = [
    {
      title: intl.formatMessage({ id: 'cloudAccount.extend.title.cloud.platform' }),
      dataIndex: 'platform',
      key: 'platform',
      render: (platform: string) => obtainPlatformEasyIcon(platform, platformList),
    },
    {
      title: intl.formatMessage({ id: 'cloudAccount.extend.title.account.id' }),
      dataIndex: 'cloudAccountId',
      key: 'cloudAccountId',
      render: (text: string, record: API.CollectorRecord) => (
        <div>
          <div>{text}</div>
          <div style={{ fontSize: '12px', color: '#888' }}>{record.alias}</div>
        </div>
      ),
    },
    {
      title: intl.formatMessage({ id: 'cloudAccount.table.column.collector.name' }),
      dataIndex: 'collectorName',
      key: 'collectorName',
      ellipsis: true,
      render: (text: string) => (
        <Tooltip title={text}>
          <span>{text}</span>
        </Tooltip>
      ),
    },
    {
      title: intl.formatMessage({ id: 'cloudAccount.table.column.start.time' }),
      dataIndex: 'startTime',
      key: 'startTime',
    },
    {
      title: intl.formatMessage({ id: 'cloudAccount.table.column.end.time' }),
      dataIndex: 'endTime',
      key: 'endTime',
    },
    {
      title: "Metadata",
      dataIndex: 'collectRecordInfo',
      key: 'collectRecordInfo',
      width: 200,
      render: (collectRecordInfo: any, record: API.CollectorRecord) => {
          /**
           * Parse and handle metadata display - deserialize collectRecordInfo for better readability
           */
          let parsedMetadata = null;
          
          // Try to parse collectRecordInfo if it's a string
          if (collectRecordInfo) {
            try {
              parsedMetadata = typeof collectRecordInfo === 'string' 
                ? JSON.parse(collectRecordInfo) 
                : collectRecordInfo;
            } catch (error) {
              console.warn('Failed to parse collectRecordInfo:', error);
              parsedMetadata = collectRecordInfo;
            }
          }
          
          const handleShowMetadata = () => {
            setSelectedMetadata(parsedMetadata);
            setMetadataModalVisible(true);
          };
          
          // Check if metadata exists
          if (!parsedMetadata) {
            return <span style={{ color: '#999' }}>No metadata</span>;
          }
        
        return (
          <div 
            style={{ 
              cursor: 'pointer',
              padding: '4px 8px',
              borderRadius: '4px',
              border: '1px solid #d9d9d9',
              backgroundColor: '#fafafa',
              transition: 'all 0.3s'
            }} 
            onClick={handleShowMetadata}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = '#e6f7ff';
              e.currentTarget.style.borderColor = '#1890ff';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = '#fafafa';
              e.currentTarget.style.borderColor = '#d9d9d9';
            }}
          >
            <Space>
              <InfoCircleOutlined style={{ color: '#1890ff' }} />
              <span style={{ color: '#1890ff', fontSize: '12px' }}>View Details</span>
            </Space>
          </div>
        );
      },
    },
    {
      title: intl.formatMessage({ id: 'cloudAccount.table.column.status' }),
      dataIndex: 'percent',
      key: 'status',
      render: (percent: number, record: any) => {
        if (percent !== null && percent < 100 && record.endTime == null) {
          return (
            <Progress
              percent={percent}
              size="small"
              status={percent === 100 ? 'success' : 'active'}
              strokeColor={percent === 100 ? '#52c41a' : '#1890ff'}
            />
          );
        }
        return (
          <Tag color="success" icon={<CheckCircleOutlined />}>
            Completed
          </Tag>
        );
      },
    },
    {
      title: intl.formatMessage({ id: 'cloudAccount.table.column.error.number' }),
      dataIndex: 'errorResourceTypeList',
      key: 'errorResourceTypeList',
      render: (types: string[], record: API.CollectorRecord) => (
        <a
          onClick={() => {
            history.push(`/cloudAccount/collectionRecord/${record.id}`);
          }}
        >
          <Space>
            {types?.length || 0}
            {types?.length > 0 && <CloseCircleFilled style={{ color: '#ff4d4f' }} />}
          </Space>
        </a>
      ),
    },
  ];

  return (
    <PageContainer
      title={intl.formatMessage({
        id: 'cloudAccount.title.collection.record',
      })}
      extra={(
        <Form form={form} layout="inline">
          <Form.Item>
          <Select
            style={{ minWidth: 200, maxWidth: '100%' }}
            options={platformList?.map((item: any) => ({
              ...item,
              label: (
                <Space>
                  {obtainPlatformEasyIcon(item.value, platformList)}
                  {item.label}
                </Space>
              ),
            }))}
            value={selectedPlatform}
            onChange={(value) => {
              setSelectedPlatform(value);
              setSelectedAccount('');
              setCurrent(1);
            }}
          />
          </Form.Item>
          <Form.Item>
            <Select
              placeholder={intl.formatMessage({ id: 'cloudAccount.extend.title.account.id' })}
              style={{ width: 200 }}
              value={selectedAccount}
              onChange={(value) => {
                setSelectedAccount(value);
                setSelectedErrorCode('');
              }}
              options={accountOptions}
              allowClear
              showSearch
              filterOption={false}
              onSearch={(value) => {
                fetchAccountList(selectedPlatform, value);
              }}
            />
          </Form.Item>
          <Form.Item>
            <Select
              placeholder={intl.formatMessage({ id: 'cloudAccount.table.column.error.number' })}
              style={{ width: 200 }}
              value={selectedErrorCode}
              onChange={(value) => setSelectedErrorCode(value)}
              options={errorCodeOptions}
              allowClear
            />
          </Form.Item>
          <Form.Item>
            <RangePicker
              showTime
              value={timeRange}
              onChange={(dates) => setTimeRange(dates as [dayjs.Dayjs | null, dayjs.Dayjs | null])}
            />
          </Form.Item>

          <Form.Item>
            <Button type="primary" onClick={handleSearch}>
              {intl.formatMessage({ id: 'common.button.text.query' })}
            </Button>
          </Form.Item>
        </Form>
      )}
    >
      <Table
        columns={columns}
        dataSource={data}
        rowKey="id"
        loading={loading}
        scroll={{ x: 'max-content' }}
        pagination={{
          current,
          pageSize,
          total,
          showSizeChanger: true,
          showQuickJumper: true,
          onChange: (page, size) => {
            setCurrent(page);
            setPageSize(size);
          },
        }}
      />
      
      {/* Metadata Detail Modal */}
       <Modal
         title={
           <Space>
             <InfoCircleOutlined style={{ color: '#1890ff' }} />
             <span>Metadata Details</span>
           </Space>
         }
         open={metadataModalVisible}
         onCancel={handleModalClose}
         footer={[
           <Button 
             key="fullscreen" 
             icon={isFullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
             onClick={toggleFullscreen}
           >
             {isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
           </Button>,
         ]}
         width={isFullscreen ? '100vw' : 800}
         style={isFullscreen ? {
           top: 0,
           paddingBottom: 0,
           maxWidth: '100vw'
         } : {}}
         bodyStyle={isFullscreen ? {
           height: 'calc(100vh - 110px)',
           padding: '24px'
         } : {}}
       >         <JSONEditor
           value={selectedMetadata ? 
             (typeof selectedMetadata === 'object' 
               ? JSON.stringify(selectedMetadata, null, 2)
               : selectedMetadata
             ) : '{}'
           }
           readOnly={true}
           editorStyle={{
             height: isFullscreen ? 'calc(100vh - 200px)' : '60vh',
             border: '1px solid #e1e4e8',
             borderRadius: '6px'
           }}
         />
       </Modal>
    </PageContainer>
  );
};

export default CollectionRecord;
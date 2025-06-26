import { useIntl, useModel, useParams, useRequest } from '@umijs/max';
import { obtainPlatformEasyIcon } from '@/utils/shared';
import { PageContainer } from '@ant-design/pro-components';
import { Card, Descriptions, Table, Tooltip } from 'antd';
import { useEffect, useState } from 'react';
import { getCollectionRecordDetail } from '@/services/account/AccountCollectorRecord';

const CollectionRecordDetail: React.FC = () => {
  const { platformList } = useModel('rule');
  const intl = useIntl();
  const { id } = useParams<{ id: string }>();
  const [record, setRecord] = useState<API.CollectionRecord>();
  const [loading, setLoading] = useState(false);
  const [current, setCurrent] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [cloudAccountId] = id.split('_');
      const response = await getCollectionRecordDetail({
        id: parseInt(id, 10),
      });
      setRecord(response.content);
    } catch (error) {
      console.error('获取采集记录详情失败:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (id) {
      fetchData();
    }
  }, [id]);

  const columns = [
    {
      title: intl.formatMessage({ id: 'cloudAccount.extend.title.asset.type' }),
      dataIndex: 'resourceType',
      key: 'resourceType',
      render: (_: string, record: API.ErrorDetail) => `${record.resourceTypeName} (${record.resourceType})`,
    },
    {
      title: intl.formatMessage({ id: 'cloudAccount.table.column.error.details' }),
      dataIndex: 'errorDetailItems',
      key: 'errorDetailItems',
      render: (items: API.ErrorDetailItem[]) => (
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {items.map((item, index) => (
            <li key={index} style={{ marginBottom: index < items.length - 1 ? 8 : 0 }}>
              <div><strong>{item.description}</strong></div>
              <div style={{ display: 'flex', width: '100%' }}>
                <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', flex: 1, minWidth: 0, wordBreak: 'break-all' }}>
                  <Tooltip title={item.message}>
                    <span>{item.message}</span>
                  </Tooltip>
                </div>
              </div>
              <div style={{ color: '#888' }}>{item.time}</div>
            </li>
          ))}
        </ul>
      ),
    },
  ];

  return (
    <PageContainer
      title={intl.formatMessage({ id: 'cloudAccount.collection.record.detail' })}
      loading={loading}
    >
      <Card>
        <Descriptions title={intl.formatMessage({ id: 'cloudAccount.extend.title.basic.information' })}>
          <Descriptions.Item label={intl.formatMessage({ id: 'cloudAccount.extend.title.cloud.platform' })}>
            {obtainPlatformEasyIcon(record?.platform, platformList)}
          </Descriptions.Item>
          <Descriptions.Item label={intl.formatMessage({ id: 'cloudAccount.extend.title.account.alias' })}>
            {record?.alias}
          </Descriptions.Item>
          <Descriptions.Item label={intl.formatMessage({ id: 'cloudAccount.extend.title.account.id' })}>
            {record?.cloudAccountId}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Card
        style={{ marginTop: 24 }}
        title={intl.formatMessage({ id: 'cloudAccount.error.resource.errorTypes' })}
      >
        <Table
          columns={columns}
          dataSource={record?.errorDetails}
          rowKey="resourceType"
          pagination={{
            current,
            pageSize,
            total: record?.errorDetails?.length || 0,
            onChange: (page, size) => {
              setCurrent(page);
              setPageSize(size);
            },
            showSizeChanger: true,
            showQuickJumper: true
          }}
        />
      </Card>
    </PageContainer>
  );
};

export default CollectionRecordDetail;
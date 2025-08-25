import { queryRuleGroupList } from '@/services/rule/RuleController';
import { showTotalIntlFunc } from '@/utils/shared';
import { useMediaQuerySize } from '@/utils/useMediaQuery';
import { PageContainer, ProCard } from '@ant-design/pro-components';
import { useIntl, useModel, useRequest } from '@umijs/max';
import {
  Button,
  Col,
  Empty,
  Flex,
  Form,
  Input,
  Pagination,
  Row,
  Select,
  Space,
  Spin,
} from 'antd';
import { isEmpty } from 'lodash';
import React, { useEffect, useRef, useState } from 'react';
import PermissionWrapper from '@/components/Common/PermissionWrapper';
import EditModalForm from './components/EditModalForm';
import GroupCard from './components/GroupCard';
import styles from './index.less';

const DEFAULT_PAGE_NUMBER = 1;
const DEFAULT_PAGE_SIZE = 12;

const RuleGroupContent: React.FC = () => {
  // Global Props
  const { ruleGroupList } = useModel('rule');
  // CurrentMediaSize
  const mediaSize = useMediaQuerySize({});
  // CREATE ｜ EDIT ModalForm VISIBLE
  const [editFormVisible, setEditFormVisible] = useState<boolean>(false);
  // RuleGroupInfo
  const groupInfoRef = useRef<any>({});
  // From Instance
  const [form] = Form.useForm();
  // Intl API
  const intl = useIntl();
  // CurrentPage
  const [current, setCurrent] = useState<number>(DEFAULT_PAGE_NUMBER);
  // PageSize
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE);

  // Cloud account list data
  const {
    data: ruleGroupData,
    run: requestRuleGroupList,
    loading: ruleGroupListLoading,
  } = useRequest(
    (params: API.CloudAccountResult) => {
      return queryRuleGroupList(params);
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
    await requestRuleGroupList({
      page: DEFAULT_PAGE_NUMBER,
      size: DEFAULT_PAGE_SIZE,
    });
  };

  // Request data based on filtering criteria
  const requestCurrentData = async (): Promise<void> => {
    setCurrent(DEFAULT_PAGE_NUMBER);
    setPageSize(DEFAULT_PAGE_SIZE);
    const formData = form.getFieldsValue();
    await requestRuleGroupList({
      ...formData,
      page: DEFAULT_PAGE_NUMBER,
      size: DEFAULT_PAGE_SIZE,
    });
  };

  useEffect((): void => {
    requestRuleGroupList({
      page: current,
      size: pageSize,
    });
  }, []);

  // Reset
  const onClickToReset = (): void => {
    form.resetFields();
  };

  // Query
  const onClickToFinish = (formData: Record<string, any>): void => {
    setCurrent(DEFAULT_PAGE_NUMBER);
    setPageSize(DEFAULT_PAGE_SIZE);
    requestRuleGroupList({
      ...formData,
      page: DEFAULT_PAGE_NUMBER,
      size: DEFAULT_PAGE_SIZE,
    });
  };

  return (
    <PageContainer
      ghost
      title={false}
      className={styles['rulePageContainer']}
      breadcrumbRender={false}
    >
      <ProCard style={{ marginBottom: 16 }}>
        <Form form={form} onFinish={onClickToFinish}>
          <Row gutter={[24, 10]}>
            <Col span={6}>
              <Form.Item
                name="ruleGroupIdList"
                label={intl.formatMessage({
                  id: 'rule.input.text.rule.group.name',
                })}
                style={{ marginBottom: 0 }}
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
                name="username"
                label={intl.formatMessage({
                  id: 'rule.input.text.rule.group.creator',
                })}
                style={{ marginBottom: 0 }}
              >
                <Input
                  placeholder={intl.formatMessage({
                    id: 'common.input.text.placeholder',
                  })}
                  allowClear
                />
              </Form.Item>
            </Col>
            <Col span={6} push={6}>
              <Flex style={{ width: '100%' }} justify={'flex-end'}>
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
                      loading={ruleGroupListLoading}
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
              groupInfoRef.current = {};
            }}
          >
            {intl.formatMessage({
              id: 'rule.extend.group.add',
            })}
          </Button>
        </Row>

        <Row className={styles['ruleGroupWrap']}>
          <Spin spinning={ruleGroupListLoading}>
            {!isEmpty(ruleGroupData?.data) ? (
              <Row gutter={[16, 16]}>
                {ruleGroupData?.data?.map((ruleGroup: API.RuleGroupInfo) => (
                  <Col
                    span={
                      ['xxLProMax']?.includes(mediaSize)
                        ? 4
                        : ['xxLFullHD', 'xxLPro']?.includes(mediaSize)
                        ? 6
                        : ['xxL', 'xL']?.includes(mediaSize)
                        ? 8
                        : ['lg', 'md']?.includes(mediaSize)
                        ? 12
                        : 24
                    }
                    key={ruleGroup.id}
                  >
                    <GroupCard
                      key={ruleGroup.id}
                      ruleGroup={ruleGroup}
                      requestInitData={requestInitData}
                      requestCurrentData={requestCurrentData}
                    />
                  </Col>
                ))}
              </Row>
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
                requestRuleGroupList({
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
              total={ruleGroupData?.total || 0}
              showSizeChanger={true}
              pageSizeOptions={[12, 24]}
            />
          </Flex>
        </Row>
      </ProCard>

      <EditModalForm
        editFormVisible={editFormVisible}
        setEditFormVisible={setEditFormVisible}
        groupInfo={groupInfoRef.current}
        requestCurrentData={requestCurrentData}
      />
    </PageContainer>
  );
};

const RuleGroup: React.FC = () => {
  return (
      <RuleGroupContent />
  );
};

export default RuleGroup;

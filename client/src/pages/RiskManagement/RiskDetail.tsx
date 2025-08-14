import DISCOVER from '@/assets/images/DISCOVER.svg';
import SCAN from '@/assets/images/SCAN.svg';
import Disposition from '@/components/Disposition';
import NoPermission from '@/components/Common/NoPermission';
import CheckInform from '@/pages/RiskManagement/components/CheckInform';
import {
  IgnoreReasonTypeList,
  RiskStatusList,
} from '@/pages/RiskManagement/const';
import styles from '@/pages/RiskManagement/index.less';
import { queryRiskDetailById } from '@/services/risk/RiskController';
import { IValueType } from '@/utils/const';
import { obtainPlatformIcon, obtainRiskStatus } from '@/utils/shared';
import { ArrowLeftOutlined, ProfileOutlined } from '@ant-design/icons';
import { PageContainer, ProCard } from '@ant-design/pro-components';
import { history, useLocation, useModel, useRequest, useIntl } from '@umijs/max';
import {
  Button,
  Card,
  ConfigProvider,
  Flex,
  Form,
  Space,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import React, { useEffect, useState } from 'react';
import EvaluateDrawer from './components/EvaluateDrawer';
import LogInformation from './components/LogInformation';
import ResourceDrawer from './components/ResourceDrawer';
const { Text } = Typography;

/**
 * Risk Management - Risk Details
 * Note: Not yet used
 */

const RiskDetail: React.FC = () => {
  // Get routing parameters
  const location = useLocation();
  const queryParameters: URLSearchParams = new URLSearchParams(location.search);
  const [id] = useState(queryParameters.get('id'));
  // Intl API
  const intl = useIntl();
  // Global List
  const { platformList } = useModel('rule');
  const { tenantListAll } = useModel('tenant');
  // Testing situation
  const [evaluateDrawerVisible, setEvaluateDrawerVisible] =
    useState<boolean>(false);
  // Asset Details
  const [resourceDrawerVisible, setResourceDrawerVisible] =
    useState<boolean>(false);

  // Error state for no permission
  const [hasError, setHasError] = useState<boolean>(false);

  // Risk detail data
  const {
    data: riskInfo,
    run: requestRiskDetailById,
    loading: riskDetailLoading,
  }: any = useRequest(
    (id) => {
      return queryRiskDetailById({ riskId: id });
    },
    {
      manual: true,
      formatResult: (r: any) => {
        if(r.code === 403){
          setHasError(true);
        }
        return r.content || {};
      },
      onError: (error: any) => {
        setHasError(true);
      },
    },
  );

  useEffect((): void => {
    if (id) requestRiskDetailById(id);
  }, [id]);

  // Show error page when access is denied
  if (hasError) {
    return (
      <PageContainer
        breadcrumbRender={false}
        title={
          <Button type={'link'} size={'small'} onClick={() => history?.back()}>
            <ArrowLeftOutlined /> {intl.formatMessage({ id: 'common.button.text.return' })}
          </Button>
        }
        className={styles['riskDetailContainer']}
      >
        <NoPermission />
      </PageContainer>
    );
  }

  return (
    <PageContainer
      loading={riskDetailLoading}
      breadcrumbRender={false}
      title={
        <Flex justify="space-between" align="center" style={{ width: '100%' }}>
          <Button type={'link'} size={'small'} onClick={() => history?.back()}>
            <ArrowLeftOutlined /> {intl.formatMessage({ id: 'common.button.text.return' })}
          </Button>
        </Flex>
      }
      className={styles['riskDetailContainer']}
    >
      <Card className={styles['riskDetailAroundCard']}>
        <ProCard
          style={{ marginBottom: 18 }}
          bodyStyle={{
            backgroundColor: '#f9f9f9',
            padding: '16px 20px',
          }}
        >
          <Flex
            justify={'space-between'}
            align={'center'}
            style={{ marginBottom: 10 }}
          >
            <span>
              <Text style={{ marginRight: 12 }}>
                <Button
                  type={'link'}
                  href={`/ruleManagement/ruleProject/edit?id=${riskInfo?.ruleId}`}
                  target={'_blank'}
                  style={{ padding: '4px 0 4px 4px', fontSize: '18px' }}
                >
                  {riskInfo?.ruleVO?.ruleName || '-'}
                </Button>
              </Text>

              <Space>
                {/* Risk status */}
                <span>
                  {obtainRiskStatus(RiskStatusList, riskInfo?.status)}
                </span>
                {riskInfo?.ignoreReasonType && (
                  <span>
                    <Text
                      style={{
                        marginRight: 8,
                        color: 'rgba(127, 127, 127, 1)',
                      }}
                    >
                      {intl.formatMessage({
                        id: 'risk.module.text.ignore.type',
                      })}
                      &nbsp;:&nbsp;
                    </Text>
                    <Tag color="geekblue">
                      {IgnoreReasonTypeList.find(
                        (item: IValueType): boolean =>
                          item.value === riskInfo?.ignoreReasonType,
                      )?.label || '-'}
                    </Tag>
                  </span>
                )}
                {riskInfo?.ignoreReason && (
                  <>
                    <Text
                      style={{
                        marginRight: 8,
                        color: 'rgba(127, 127, 127, 1)',
                      }}
                    >
                      {intl.formatMessage({
                        id: 'risk.module.text.ignore.reason',
                      })}
                      &nbsp;:&nbsp;
                    </Text>
                    <Disposition
                      rows={1}
                      text={riskInfo?.ignoreReason}
                      maxWidth={64}
                    />
                  </>
                )}
              </Space>
            </span>
            {/*<Button*/}
            {/*  type={'link'}*/}
            {/*  onClick={() => setEvaluateDrawerVisible(true)}*/}
            {/*>*/}
            {/*  <Flex align={'center'}>*/}
            {/*    <img*/}
            {/*      src={RISK_EVALUATE}*/}
            {/*      style={{ width: 18, height: 18, marginRight: 4 }}*/}
            {/*      alt={'RISK_EVALUATE'}*/}
            {/*    />*/}
            {/*    <span style={{ textDecoration: 'underline', color: '#457aff' }}>*/}
            {/*      检测情况*/}
            {/*    </span>*/}
            {/*  </Flex>*/}
            {/*</Button>*/}
          </Flex>
          <Flex vertical={true} gap={10}>
            <Flex align={'center'}>
              <img
                src={SCAN}
                alt="DISCOVER_ICON"
                style={{ width: 14, height: 14 }}
              />
              <span
                style={{
                  color: 'rgba(127, 127, 127, 1)',
                  margin: '0 8px 0 6px',
                }}
              >
                {intl.formatMessage({
                  id: 'risk.module.text.recently.scanned.hits',
                })}
                &nbsp;:&nbsp;
              </span>
              <span style={{ color: 'rgba(51, 51, 51, 1)' }}>
                {riskInfo?.gmtModified}
              </span>
            </Flex>
            <Text>
              <img
                src={DISCOVER}
                alt="DISCOVER_ICON"
                style={{ width: 14, height: 14 }}
              />
              <span
                style={{
                  color: 'rgba(127, 127, 127, 1)',
                  margin: '0 8px 0 6px',
                }}
              >
                {intl.formatMessage({
                  id: 'risk.module.text.first.discovery.time',
                })}
                &nbsp;:&nbsp;
              </span>
              <span style={{ color: 'rgba(51, 51, 51, 1)' }}>
                {riskInfo?.gmtCreate}
              </span>
            </Text>
          </Flex>

          {/* Cloud Account Information */}
          <Flex
            align={'center'}
            style={{ margin: '10px 0 6px 0' }}
          >
            <span
              style={{
                marginRight: 8,
                color: 'rgba(127, 127, 127, 1)',
              }}
            >
              {intl.formatMessage({
                id: 'common.select.label.cloudAccount',
              })}
              &nbsp;:&nbsp;
            </span>
            <span style={{ color: 'rgba(51, 51, 51, 1)', marginRight: 16 }}>
              {riskInfo?.cloudAccountId || '-'}
            </span>
            <span style={{ color: 'rgba(127, 127, 127, 1)', marginRight: 16 }}>
              {riskInfo?.alias || '-'}
            </span>
          </Flex>

          <Flex
            justify={'start'}
            align={'center'}
            style={{ margin: '10px 0 6px 0' }}
          >
            <span style={{ marginRight: 5, color: 'rgba(127, 127, 127, 1)' }}>
              {obtainPlatformIcon(riskInfo?.platform, platformList)}
            </span>
            <Text style={{ marginRight: 20, color: 'rgba(127, 127, 127, 1)' }}>
              {riskInfo?.resourceType || '-'}
            </Text>
            <Flex align={'center'}>
              <span
                style={{
                  marginRight: 4,
                  color: 'rgba(127, 127, 127, 1)',
                }}
              >
                {riskInfo?.resourceName + ' / ' + riskInfo?.resourceId}
              </span>

              <Tooltip title={intl.formatMessage({ id: 'asset.extend.text.detail' })}>
                <span
                  className={styles['iconWrap']}
                  onClick={() => setResourceDrawerVisible(true)}
                >
                  <ProfileOutlined className={styles['resourceInstance']} />
                </span>
              </Tooltip>
            </Flex>
            <Text style={{ color: 'rgba(127, 127, 127, 1)', margin: '0 12px' }}>
              {tenantListAll?.find(
                (item: IValueType) => item.value === riskInfo?.tenantId,
              )?.label || '-'}
            </Text>
          </Flex>
        </ProCard>

        <ConfigProvider
          theme={{
            components: {
              Form: {
                itemMarginBottom: 8,
                labelColor: 'rgba(127, 127, 127, 1)',
                labelColonMarginInlineEnd: 16,
              },
            },
          }}
        >
          <Form>
            <Form.Item label={intl.formatMessage({ id: 'rule.module.text.repair.suggestions' })}>
              <span style={{ color: 'rgb(51, 51, 51)' }}>
                {riskInfo?.ruleVO?.advice || '-'}
              </span>
            </Form.Item>
            <Form.Item label={intl.formatMessage({ id: 'risk.module.text.reference.link' })}>
              <span style={{ color: 'rgb(51, 51, 51)' }}>
                {riskInfo?.ruleVO?.link || '-'}
              </span>
            </Form.Item>
            <Form.Item label={intl.formatMessage({ id: 'rule.module.text.rule.describe' })}>
              <span style={{ color: 'rgb(51, 51, 51)' }}>
                {riskInfo?.ruleVO?.ruleDesc || '-'}
              </span>
            </Form.Item>
          </Form>
        </ConfigProvider>

        {/** Testing situation **/}
        <CheckInform riskDrawerInfo={riskInfo} />

        {/** Logging - Add Log **/}
        <LogInformation riskDrawerInfo={riskInfo} />

        <EvaluateDrawer // Testing situation
          evaluateDrawerVisible={evaluateDrawerVisible}
          setEvaluateDrawerVisible={setEvaluateDrawerVisible}
          riskDrawerInfo={riskInfo}
        />

        <ResourceDrawer // Asset Details
          resourceDrawerVisible={resourceDrawerVisible}
          setResourceDrawerVisible={setResourceDrawerVisible}
          riskDrawerInfo={riskInfo}
        />
      </Card>
    </PageContainer>
  );
};

export default RiskDetail;

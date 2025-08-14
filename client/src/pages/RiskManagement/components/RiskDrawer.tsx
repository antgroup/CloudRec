import DISCOVER from '@/assets/images/DISCOVER.svg';
import SCAN from '@/assets/images/SCAN.svg';
import Disposition from '@/components/Disposition';
import CheckInform from '@/pages/RiskManagement/components/CheckInform';
import EvaluateDrawer from '@/pages/RiskManagement/components/EvaluateDrawer';
import LogInformation from '@/pages/RiskManagement/components/LogInformation';
import ResourceDrawer from '@/pages/RiskManagement/components/ResourceDrawer';
import {
  IgnoreReasonTypeList,
  RiskStatusList,
} from '@/pages/RiskManagement/const';
import EditDrawerForm from '@/pages/RuleManagement/WhiteList/components/EditDrawerForm';
import { queryRiskDetailById } from '@/services/risk/RiskController';
import { IValueType } from '@/utils/const';
import { obtainPlatformIcon, obtainRiskStatus } from '@/utils/shared';
import { ProfileOutlined, EyeOutlined, ShareAltOutlined } from '@ant-design/icons';
import { ActionType, ProCard } from '@ant-design/pro-components';
import { useIntl, useModel, useRequest } from '@umijs/max';
import {
  Button,
  ConfigProvider,
  Drawer,
  Flex,
  Form,
  Space,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import React, { Dispatch, SetStateAction, useEffect, useState, useCallback } from 'react';
import styles from '../index.less';
const { Text } = Typography;

interface IRiskDrawerProps {
  riskDrawerVisible: boolean;
  setRiskDrawerVisible: Dispatch<SetStateAction<boolean>>;
  riskDrawerInfo: Record<string, any>;
  tableActionRef?: React.RefObject<ActionType | undefined>;
  locate: 'risk' | 'asset';
}

// Risk Details
const RiskDrawer: React.FC<IRiskDrawerProps> = (props) => {
  // Component Props
  const { riskDrawerVisible, riskDrawerInfo, setRiskDrawerVisible, locate } =
    props;
  // Global Props
  const { platformList } = useModel('rule');
  const { tenantListAll } = useModel('tenant');
  // Intl API
  const intl = useIntl();
  // Testing situation
  const [evaluateDrawerVisible, setEvaluateDrawerVisible] =
    useState<boolean>(false);
  // Asset Details
  const [resourceDrawerVisible, setResourceDrawerVisible] =
    useState<boolean>(false);
  // Whitelist Details
  const [whiteListDrawerVisible, setWhiteListDrawerVisible] =
    useState<boolean>(false);

  const initDrawer = (): void => {
    setRiskDrawerVisible(false);
  };

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
        return r.content || {};
      },
    },
  );

  const onClickCloseDrawerForm = (): void => {
    initDrawer();
  };

  /**
   * Share function - copy risk detail page URL to clipboard
   * Uses modern Clipboard API with fallback for older browsers
   */
  const handleShare = useCallback((): void => {
    if (!riskDrawerInfo?.id) {
      message.error(intl.formatMessage({
        id: 'common.message.text.copy.failed',
      }));
      return;
    }

    const riskDetailUrl = `${window.location.origin}/riskManagement/riskDetail?id=${riskDrawerInfo.id}`;
    
    // Modern Clipboard API with fallback
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(riskDetailUrl).then(() => {
        message.success(intl.formatMessage({
          id: 'common.message.text.copy.success',
        }));
      }).catch(() => {
        fallbackCopyTextToClipboard(riskDetailUrl);
      });
    } else {
      // Fallback for older browsers or insecure contexts
      fallbackCopyTextToClipboard(riskDetailUrl);
    }
  }, [riskDrawerInfo?.id, intl]);

  /**
   * Fallback method for copying text to clipboard
   * Creates a temporary textarea element to perform the copy operation
   */
  const fallbackCopyTextToClipboard = useCallback((text: string): void => {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    
    // Avoid scrolling to bottom and make invisible
    textArea.style.top = '0';
    textArea.style.left = '0';
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    textArea.style.pointerEvents = 'none';
    textArea.style.zIndex = '-1';
    
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
      const successful = document.execCommand('copy');
      if (successful) {
        message.success(intl.formatMessage({
          id: 'common.message.text.copy.success',
        }));
      } else {
        message.error(intl.formatMessage({
          id: 'common.message.text.copy.failed',
        }));
      }
    } catch (err) {
      console.error('Fallback copy failed:', err);
      message.error(intl.formatMessage({
        id: 'common.message.text.copy.failed',
      }));
    } finally {
      // Ensure cleanup even if an error occurs
      if (document.body.contains(textArea)) {
        document.body.removeChild(textArea);
      }
    }
  }, [intl]);

  useEffect((): void => {
    if (riskDrawerVisible && riskDrawerInfo?.id) {
      requestRiskDetailById(riskDrawerInfo.id);
    }
  }, [riskDrawerVisible, riskDrawerInfo]);

  return (
    <>
      <Drawer
        title={
          <Flex justify="space-between" align="center">
            <span>
              {intl.formatMessage({
                id: 'risk.module.text.detail.info',
              })}
            </span>
            <Tooltip title={intl.formatMessage({ id: 'common.button.text.share' })}>
              <Button
                type="text"
                icon={<ShareAltOutlined />}
                onClick={handleShare}
                style={{ marginRight: -8 }}
                aria-label={intl.formatMessage({ id: 'common.button.text.share' })}
              />
            </Tooltip>
          </Flex>
        }
        width={'50%'}
        open={riskDrawerVisible}
        onClose={onClickCloseDrawerForm}
        loading={riskDetailLoading}
      >
        <ProCard
          style={{ marginBottom: 20 }}
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
                {/* Whitelist button - show only when risk is whitelisted */}
                {riskInfo?.whitedId && (
                    <Button
                      type="link"
                      size="small"
                      icon={<EyeOutlined />}
                      onClick={() => setWhiteListDrawerVisible(true)}
                      style={{
                        padding: '0 4px',
                        height: 'auto',
                        color: '#1890ff',
                      }}
                    />
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
            {/*      alt="RISK_EVALUATE_ICON"*/}
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

              {locate === 'risk' && (
                <Tooltip
                  title={intl.formatMessage({
                    id: 'asset.extend.text.detail',
                  })}
                >
                  <span
                    className={styles['iconWrap']}
                    onClick={() => setResourceDrawerVisible(true)}
                  >
                    <ProfileOutlined className={styles['resourceInstance']} />
                  </span>
                </Tooltip>
              )}
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
            <Form.Item
              label={intl.formatMessage({
                id: 'rule.module.text.repair.suggestions',
              })}
            >
              <span style={{ color: 'rgb(51, 51, 51)' }}>
                {riskInfo?.ruleVO?.advice || '-'}
              </span>
            </Form.Item>
            <Form.Item
              label={intl.formatMessage({
                id: 'risk.module.text.reference.link',
              })}
            >
              <span style={{ color: 'rgb(51, 51, 51)' }}>
                {riskInfo?.ruleVO?.link || '-'}
              </span>
            </Form.Item>
            <Form.Item
              label={intl.formatMessage({
                id: 'rule.module.text.rule.describe',
              })}
            >
              <span style={{ color: 'rgb(51, 51, 51)' }}>
                {riskInfo?.ruleVO?.ruleDesc || '-'}
              </span>
            </Form.Item>
          </Form>
        </ConfigProvider>

        {/** Testing situation **/}
        <CheckInform riskDrawerInfo={riskDrawerInfo} />

        {/** Logging - Add Log **/}
        <LogInformation riskDrawerInfo={riskDrawerInfo} />
      </Drawer>

      <EvaluateDrawer // Testing situation
        evaluateDrawerVisible={evaluateDrawerVisible}
        setEvaluateDrawerVisible={setEvaluateDrawerVisible}
        riskDrawerInfo={riskDrawerInfo}
      />

      <ResourceDrawer // Asset Details
        resourceDrawerVisible={resourceDrawerVisible}
        setResourceDrawerVisible={setResourceDrawerVisible}
        riskDrawerInfo={riskDrawerInfo}
      />

      {/* Whitelist Details Drawer */}
      {riskInfo?.whitedId && (
        <EditDrawerForm
          editDrawerVisible={whiteListDrawerVisible}
          setEditDrawerVisible={setWhiteListDrawerVisible}
          whiteListDrawerInfo={{
            id: riskInfo.whitedId,
            isEditMode: false, // Read-only mode for viewing whitelist details
          }}
        />
      )}
    </>
  );
};

export default RiskDrawer;

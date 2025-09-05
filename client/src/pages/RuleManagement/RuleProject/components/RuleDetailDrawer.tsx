import React, { useState, useEffect } from 'react';
import { Drawer, Descriptions, Tag, Spin, message, Typography } from 'antd';
import { useIntl } from '@umijs/max';
import { queryRuleDetail } from '@/services/rule/RuleController';
import { obtainRiskLevel, obtainPlatformEasyIcon } from '@/utils/shared';
import { RiskLevelList } from '@/utils/const';

interface RuleDetailDrawerProps {
  visible: boolean;
  onClose: () => void;
  ruleId?: number;
  ruleCode?: string;
}

const RuleDetailDrawer: React.FC<RuleDetailDrawerProps> = ({
  visible,
  onClose,
  ruleId,
  ruleCode,
}) => {
  const intl = useIntl();
  const [messageApi, contextHolder] = message.useMessage();
  const [loading, setLoading] = useState(false);
  const [ruleDetail, setRuleDetail] = useState<any>(null);

  useEffect(() => {
    if (visible && ruleId) {
      fetchRuleDetail();
    }
  }, [visible, ruleId]);

  const fetchRuleDetail = async () => {
    setLoading(true);
    try {
      let result;
      if (ruleId) {
        result = await queryRuleDetail({ id: ruleId } as any);
      }
      
      if (result && result.content) {
        setRuleDetail(result.content);
      }
    } catch (error) {
      messageApi.error('获取规则详情失败');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setRuleDetail(null);
    onClose();
  };

  // 获取风险等级颜色
  const getRiskLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'high':
      case '高':
        return 'red';
      case 'medium':
      case '中':
        return 'orange';
      case 'low':
      case '低':
        return 'green';
      default:
        return 'default';
    }
  };

  // 渲染风险等级标签
  const renderRiskLevelTag = (riskLevel: string) => {
    if (!riskLevel) return null;
    const riskLevels = riskLevel.split(',');
    return riskLevels.map((level, index) => (
      <Tag key={index} color={getRiskLevelColor(level.trim())}>
        {level.trim()}
      </Tag>
    ));
  };

  const getPlatformIcon = (platform: string) => {
    return obtainPlatformEasyIcon(platform);
  };

  return (
    <>
      {contextHolder}
      <Drawer
        placement="right"
        onClose={handleClose}
        open={visible}
        width={1000}
        destroyOnClose
      >
        <Spin spinning={loading}>
          {ruleDetail && (
            <Descriptions column={1} bordered>
              <Descriptions.Item label={intl.formatMessage({ id: 'home.module.inform.columns.ruleName' }, {})}>
                <Typography.Text copyable>{ruleDetail.ruleName}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="Code">
                <Typography.Text copyable>{ruleDetail.ruleCode}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label={intl.formatMessage({ id: 'rule.module.text.repair.suggestions' }, {})}>
                <Typography.Text copyable>{ruleDetail.advice}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label={intl.formatMessage({ id: 'rule.module.text.reference.link' }, {})}>
                <Typography.Text copyable>{ruleDetail.link}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label={intl.formatMessage({ id: 'rule.module.text.risk.context.template' }, {})}>
                <Typography.Text copyable>{ruleDetail.context}</Typography.Text>
              </Descriptions.Item>
              {ruleDetail.ruleRego && (
                <Descriptions.Item label="Rego Policy">
                  <Typography.Text copyable={{ text: ruleDetail.ruleRego }}>
                    <pre style={{ 
                      background: '#f5f5f5', 
                      padding: '12px', 
                      borderRadius: '4px',
                      fontSize: '12px',
                      maxHeight: '2048px',
                      overflow: 'auto'
                    }}>
                      {ruleDetail.ruleRego}
                    </pre>
                  </Typography.Text>
                </Descriptions.Item>
              )}
              
              {ruleDetail.gmtModified && (
                <Descriptions.Item label={intl.formatMessage({ id: 'common.text.update.time' }, {})}>
                  <Typography.Text copyable>{ruleDetail.gmtModified}</Typography.Text>
                </Descriptions.Item>
              )}
            </Descriptions>
          )}
        </Spin>
      </Drawer>
    </>
  );
};

export default RuleDetailDrawer;
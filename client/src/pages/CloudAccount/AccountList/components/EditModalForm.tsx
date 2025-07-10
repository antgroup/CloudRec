import { saveCloudAccount } from '@/services/account/AccountController';
import { ExportOutlined, InfoCircleOutlined } from '@ant-design/icons';
import { DrawerForm, ProFormCascader, ProFormDependency, ProFormSelect, ProFormText } from '@ant-design/pro-components';
import { useIntl, useModel } from '@umijs/max';
import { Button, Cascader, Col, Divider, Empty, Form, Row, Spin, Tooltip, Typography, message } from 'antd';
import React, { Dispatch, SetStateAction, useEffect, useState } from 'react';
import { valueListAddIcon } from '@/utils/shared';
import CloudCredentialEditor from '@/components/CloudCredentialEditor';
import ProxyConfigForm from '@/components/ProxyConfigForm';
import { useResourceTypes } from '@/hooks/useResourceTypes';
import { PLATFORM_CONFIGS, FORM_VALIDATION_RULES } from '../config/platformConfig';
import { CloudAccountFormData, CloudAccountCredentials } from '@/components/CloudCredentialEditor/types';
import styles from './index.less';

const { SHOW_CHILD } = Cascader;
const { Text } = Typography;

interface IEditFormProps {
  editFormVisible: boolean;
  setEditFormVisible: Dispatch<SetStateAction<boolean>>;
  accountInfo: {
    id?: number;
    platform?: string;
    resourceTypeListForWeb?: string[];
    credentialMap?: CloudAccountCredentials;
    proxyConfig?: string;
    [key: string]: any;
  };
  requestCurrentData: () => Promise<void>;
}

const EditDrawerForm: React.FC<IEditFormProps> = (props) => {
  // Global Props
  const { platformList } = useModel('rule');
  const { tenantListAll } = useModel('tenant');
  const { loading: resourceListLoading, resourceTypes, fetchResourceTypes } = useResourceTypes();
  
  // Form Instance
  const [form] = Form.useForm<CloudAccountFormData>();
  const intl = useIntl();
  
  // Component Props
  const { editFormVisible, accountInfo, setEditFormVisible, requestCurrentData } = props;
  
  // State
  const [extendEditorVisible, setExtendEditorVisible] = useState<boolean>(true);
  const [jsonValue, setJsonValue] = useState<string>('{}');

  const handleCredentialChange = (value: CloudAccountCredentials) => {
    const formValues = form.getFieldsValue();
    const platform = formValues.platform;
    if (!platform) return;

    const platformConfig = PLATFORM_CONFIGS[platform];
    if (!platformConfig) return;

    if (platformConfig.type === 'json') {
      const jsonStr = value.credentialsJson || '{}';
      setJsonValue(jsonStr);
      form.setFieldsValue({
        credentials: { credentialsJson: jsonStr }
      });
    } else {
      const currentCredentials = form.getFieldValue('credentials') || {};
      const credentialsData: Partial<CloudAccountCredentials> = { ...currentCredentials };
      platformConfig.fields.forEach((field: { name: string }) => {
        const fieldName = field.name as keyof CloudAccountCredentials;
        if (fieldName in value && value[fieldName] !== undefined) {
          credentialsData[fieldName] = value[fieldName];
        }
      });
      form.setFieldsValue({
        credentials: credentialsData
      });
    }
  };

  // 提交表单
  const onClickFishEditForm = async (): Promise<void> => {
    const formData = form.getFieldsValue() as CloudAccountFormData;
    const { cloudAccountId,email, alias, tenantId, platform, resourceTypeList, site, owner, proxyConfig, credentials } = formData;
    
    const postBody: {
      id?: number;
      cloudAccountId: string;
      email: string;
      alias: string;
      tenantId?: number;
      platform: string;
      resourceTypeList?: string[];
      site?: string;
      owner?: string;
      credentialsObj?: CloudAccountCredentials;
      proxyConfig?: string;
    } = {
      cloudAccountId,
      email,
      alias,
      tenantId: typeof tenantId === 'string' ? parseInt(tenantId, 10) : tenantId,
      platform,
      resourceTypeList,
      site,
      owner
    };

    const platformConfig = PLATFORM_CONFIGS[platform];
    if (!platformConfig) return;

    // The voucher information is processed only when it is visible in the voucher editor
    if (extendEditorVisible) {
      if (platformConfig.type === 'json') {
        postBody.credentialsObj = { credentialsJson: credentials?.credentialsJson || jsonValue };
      } else {
        const credentialsData: Partial<CloudAccountCredentials> = { ...(credentials || {}) };
        platformConfig.fields.forEach((field: { name: string }) => {
          const fieldName = field.name as keyof CloudAccountCredentials;
          const fieldValue = form.getFieldValue(['credentials', fieldName]);
          if (fieldValue !== undefined) {
            credentialsData[fieldName] = fieldValue as string;
          }
        });
        postBody.credentialsObj = credentialsData;
      }
    }

    if (platformConfig.hasProxy && proxyConfig) {
      postBody.proxyConfig = proxyConfig;
    }

    if (accountInfo.id) {
      postBody.id = accountInfo.id;
    }

    const res = await saveCloudAccount(postBody);
    if (res.msg === 'success') {
      const messageKey = accountInfo.id ? 'common.message.text.edit.success' : 'common.message.text.create.success';
      message.success(intl.formatMessage({ id: messageKey }));
      setEditFormVisible(false);
      await requestCurrentData();
    }
  };

  useEffect(() => {
    if (editFormVisible && accountInfo.id) {
      setExtendEditorVisible(false as const);
      const { resourceTypeListForWeb, credentialMap, id, proxyConfig, platform, ...rest } = accountInfo;
      
      const formData: Partial<CloudAccountFormData> = {
        ...rest,
        credentials: credentialMap || {},
        resourceTypeList: resourceTypeListForWeb || [],
        proxyConfig: proxyConfig || undefined,
        platform: platform || ''
      };

      if (platform && PLATFORM_CONFIGS[platform]?.type === 'json' && credentialMap?.credentialsJson) {
        setJsonValue(credentialMap.credentialsJson);
      }

      form.setFieldsValue(formData);
      if (accountInfo.platform) {
        fetchResourceTypes(accountInfo.platform);
      }
    }
  }, [editFormVisible, accountInfo]);

  const initForm = () => {
    form.resetFields();
    setExtendEditorVisible(true);
  };

  const onCancel = () => {
    setEditFormVisible(false);
    initForm();
  };

  return (
    <DrawerForm
      labelCol={{ span: 5 }}
      wrapperCol={{ span: 17 }}
      title={
        <>
          <span style={{ marginRight: 4 }}>
            {intl.formatMessage({
              id: accountInfo.id ? 'cloudAccount.extend.title.edit' : 'cloudAccount.extend.title.add'
            })}
          </span>
          <Button
            size="small"
            type="link"
            href="https://cloudrec.yuque.com/org-wiki-cloudrec-iew3sz/hocvhx/fetbofdu8dx15q73"
            target="_blank"
            style={{ color: '#2f54eb', gap: 4 }}
          >
            <ExportOutlined />
            <span>{intl.formatMessage({ id: 'common.link.text.help.center' })}</span>
          </Button>
        </>
      }
      width={720}
      form={form}
      drawerProps={{
        destroyOnClose: true,
        onClose: onCancel,
        styles: { body: { paddingTop: 24 } },
      }}
      open={editFormVisible}
      onFinish={onClickFishEditForm}
      layout="horizontal"
    >
      <Divider className={styles.sectionDivider} dashed>
        <Text italic>
          {intl.formatMessage({ id: 'cloudAccount.extend.title.basic.information' })}
        </Text>
      </Divider>

      <Row>
        <Col span={24}>
          <ProFormText
            disabled={!!accountInfo.id}
            name="cloudAccountId"
            label={intl.formatMessage({ id: 'cloudAccount.extend.title.account.id' })}
            rules={FORM_VALIDATION_RULES.cloudAccountId}
            fieldProps={{
              suffix: !!accountInfo.id && (
                <Tooltip title="云账号ID为云平台主账号ID，创建后无法修改">
                  <InfoCircleOutlined style={{ color: 'rgba(0,0,0,.45)' }} />
                </Tooltip>
              ),
            }}
          />
        </Col>
        <Col span={24}>
          <ProFormText
            name="email"
            label={intl.formatMessage({ id: 'cloudAccount.extend.title.account.email' })}
          />
        </Col>
        <Col span={24}>
          <ProFormText
            name="alias"
            label={intl.formatMessage({ id: 'cloudAccount.extend.title.account.alias' })}
            rules={FORM_VALIDATION_RULES.alias}
          />
        </Col>

        <Col span={24}>
          <ProFormSelect
            label={intl.formatMessage({ id: 'common.select.label.tenant' })}
            name="tenantId"
            rules={FORM_VALIDATION_RULES.tenantId}
            options={tenantListAll}
            disabled={accountInfo.id && !accountInfo?.changeTenantPermission}
          />
        </Col>

        <Col span={24}>
          <ProFormText name="owner" label="Owner" />
        </Col>

        <Col span={24}>
          <ProFormSelect
            label={intl.formatMessage({ id: 'cloudAccount.extend.title.cloud.platform' })}
            name="platform"
            rules={FORM_VALIDATION_RULES.platform}
            options={valueListAddIcon(platformList, 'start') as any}
            onChange={(platform: string) => {
              if (accountInfo.id) setExtendEditorVisible(false as const);
              form.setFieldValue('resourceTypeList', undefined);
              fetchResourceTypes(platform);
            }}
          />
        </Col>
      </Row>

      <ProFormDependency name={['platform']}>
        {({ platform }) => {
          if (!platform) return null;
          const platformConfig = PLATFORM_CONFIGS[platform];
          if (!platformConfig) return null;

          return (
            <Row>
              <Col span={24}>
                <Divider className={styles.sectionDivider} dashed>
                  <Text italic>
                    {intl.formatMessage({ id: 'cloudAccount.extend.title.detailed.configuration' })}
                  </Text>
                </Divider>

                <CloudCredentialEditor
                  type={platformConfig.type}
                  fields={platformConfig.fields}
                  accountId={accountInfo.id}
                  visible={extendEditorVisible}
                  onVisibleChange={setExtendEditorVisible}
                  value={form.getFieldValue('credentials')}
                  onChange={handleCredentialChange}
                />
              </Col>

              <Col span={24}>
                <ProFormCascader
                  label={intl.formatMessage({ id: 'cloudAccount.extend.title.cloud.services' })}
                  name="resourceTypeList"
                  fieldProps={{
                    multiple: true,
                    showCheckedStrategy: SHOW_CHILD,
                    options: resourceTypes,
                    allowClear: true,
                    showSearch: true,
                    notFoundContent: resourceListLoading ? (
                      <Spin size="small" />
                    ) : (
                      <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                    ),
                  }}
                />
              </Col>

              <Col span={24}>
                <ProFormText
                  name="site"
                  label={intl.formatMessage({ id: 'cloudAccount.extend.title.cloud.site' })}
                />
              </Col>

              {platformConfig.hasProxy && (
                <Col span={24}>
                  <Divider className={styles.sectionDivider} dashed>
                    <Text italic>
                      {intl.formatMessage({ id: 'cloudAccount.form.proxy' })}
                    </Text>
                  </Divider>
                  <ProxyConfigForm />
                </Col>
              )}
            </Row>
          );
        }}
      </ProFormDependency>
    </DrawerForm>
  );
};

export default EditDrawerForm;

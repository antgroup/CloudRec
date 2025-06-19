import JSONEditor from '@/components/Editor/JSONEditor';
import { saveCloudAccount } from '@/services/account/AccountController';
import { queryGroupTypeList } from '@/services/resource/ResourceController';
import { valueListAddIcon } from '@/utils/shared';
import { ExportOutlined, InfoCircleOutlined } from '@ant-design/icons';
import {
  DrawerForm,
  ProFormCascader,
  ProFormDependency,
  ProFormSelect,
  ProFormText,
} from '@ant-design/pro-components';
import { useIntl, useModel } from '@umijs/max';
import {
  Button,
  Cascader,
  Col,
  Divider,
  Empty,
  Form,
  FormInstance,
  message,
  Row,
  Spin,
  Tooltip,
  Typography,
} from 'antd';
import { isEmpty } from 'lodash';
import React, { Dispatch, SetStateAction, useEffect, useState } from 'react';
const { SHOW_CHILD } = Cascader;
const { Text } = Typography;

interface IEditFormProps {
  editFormVisible: boolean;
  setEditFormVisible: Dispatch<SetStateAction<boolean>>;
  accountInfo: Record<string, any>;
  requestCurrentData: () => Promise<void>;
}

// [5.3] ADD_NEW_CLOUD: Display of ak/sk information
export const BASIC_EDITOR_LIST: Array<string> = [
  'ALI_CLOUD',
  'HUAWEI_CLOUD',
  'BAIDU_CLOUD',
  'AWS',
  'TENCENT_CLOUD',
  // 'My_Cloud_Provider'
  'KINGSOFT_CLOUD',
];
export const JSON_EDITOR_LIST: Array<string> = ['GCP'];
export const EXCLUSIVE_EDITOR_LIST: Array<string> = ['ALI_CLOUD_PRIVATE'];
export const EXTEND_EDITOR_LIST: Array<string> = ['HUAWEI_CLOUD_PRIVATE'];

interface IEditorModule {
  accountId: number;
  extendEditorVisible: boolean;
  setExtendEditorVisible: Dispatch<SetStateAction<boolean>>;
  jsonValue?: string;
  jsonEditorChangeCallback?: (value: string) => void;
}

const JsonEditorModule: React.FC<IEditorModule> = (props) => {
  // Component Props
  const {
    accountId,
    extendEditorVisible,
    setExtendEditorVisible,
    jsonValue,
    jsonEditorChangeCallback,
  } = props;
  // Intl API
  const intl = useIntl();

  return (
    <>
      {!!accountId && !extendEditorVisible && (
        <Form.Item
          label={intl.formatMessage({
            id: 'cloudAccount.extend.title.cloud.operate',
          })}
          name={'action'}
        >
          <Button
            type={'link'}
            onClick={(): void => setExtendEditorVisible(true)}
            style={{ padding: '4px 0', color: '#2f54eb' }}
          >
            GCP KEY &nbsp;
            {intl.formatMessage({
              id: 'common.button.text.edit',
            })}
          </Button>
        </Form.Item>
      )}
      {extendEditorVisible && (
        <ProFormText
          name="credentialsJson"
          label="GCP KEY"
          rules={[
            {
              required: true,
              validator: (): Promise<any> => {
                if (!jsonValue || jsonValue.length === 0) {
                  return Promise.reject('请输入GCP KEY');
                } else {
                  return Promise.resolve();
                }
              },
            },
          ]}
        >
          <JSONEditor
            value={jsonValue}
            onChange={jsonEditorChangeCallback}
            editorStyle={{
              height: '240px',
            }}
            editorKey="CREDENTIALS_JSONE_DITOR"
          />
        </ProFormText>
      )}
    </>
  );
};

const BasicEditorModule: React.FC<IEditorModule> = (props) => {
  // Component Props
  const { accountId, extendEditorVisible, setExtendEditorVisible } = props;
  // Intl API
  const intl = useIntl();
  return (
    <>
      {!!accountId && !extendEditorVisible && (
        <Form.Item
          label={intl.formatMessage({
            id: 'cloudAccount.extend.title.cloud.operate',
          })}
          name={'action'}
        >
          <Button
            type={'link'}
            onClick={() => setExtendEditorVisible(true)}
            style={{ padding: '4px 0', color: '#2f54eb' }}
          >
            AK、SK &nbsp;
            {intl.formatMessage({
              id: 'cloudAccount.extend.title.cloud.rotate',
            })}
          </Button>
        </Form.Item>
      )}

      {extendEditorVisible && (
        <>
          <ProFormText name="ak" label="AK" rules={[{ required: true }]} />
          <ProFormText name="sk" label="SK" rules={[{ required: true }]} />
        </>
      )}
    </>
  );
};

const ExclusiveEditorModule: React.FC<IEditorModule> = (props) => {
  // Component Props
  const { accountId, extendEditorVisible, setExtendEditorVisible } = props;
  // Intl API
  const intl = useIntl();
  return (
    <>
      {!!accountId && !extendEditorVisible && (
        <Form.Item
          label={intl.formatMessage({
            id: 'cloudAccount.extend.title.cloud.operate',
          })}
          name={'action'}
        >
          <Button
            type={'link'}
            onClick={() => setExtendEditorVisible(true)}
            style={{ padding: '4px 0', color: '#2f54eb' }}
          >
            EXCLUSIVE KEY &nbsp;
            {intl.formatMessage({
              id: 'common.button.text.edit',
            })}
          </Button>
        </Form.Item>
      )}
      {extendEditorVisible && (
        <>
          <ProFormText name="ak" label="AK" rules={[{ required: true }]} />
          <ProFormText name="sk" label="SK" rules={[{ required: true }]} />
          <ProFormText
            label="Endpoint"
            name="endpoint"
            rules={[{ required: true }]}
          />
          <ProFormText
            label="RegionId"
            name="regionId"
            rules={[{ required: true }]}
          />
        </>
      )}
    </>
  );
};

const ExtendEditorModule: React.FC<IEditorModule> = (props) => {
  // Component Props
  const { accountId, extendEditorVisible, setExtendEditorVisible } = props;
  // Intl API
  const intl = useIntl();
  return (
    <>
      {!!accountId && !extendEditorVisible && (
        <Form.Item
          label={intl.formatMessage({
            id: 'cloudAccount.extend.title.cloud.operate',
          })}
          name={'action'}
        >
          <Button
            type={'link'}
            onClick={() => setExtendEditorVisible(true)}
            style={{ padding: '4px 0', color: '#2f54eb' }}
          >
            INTACT KEY &nbsp;
            {intl.formatMessage({
              id: 'common.button.text.edit',
            })}
          </Button>
        </Form.Item>
      )}
      {extendEditorVisible && (
        <>
          <ProFormText name="ak" label="AK" rules={[{ required: true }]} />
          <ProFormText name="sk" label="SK" rules={[{ required: true }]} />
          <ProFormText
            label="Iam_Endpoint"
            name="iamEndpoint"
            rules={[{ required: true }]}
          />
          <ProFormText
            label="Ecs_Endpoint"
            name="ecsEndpoint"
            rules={[{ required: true }]}
          />
          <ProFormText
            label="Elb_Endpoint"
            name="elbEndpoint"
            rules={[{ required: true }]}
          />
          <ProFormText
            label="Evs_Endpoint"
            name="evsEndpoint"
            rules={[{ required: true }]}
          />
          <ProFormText
            label="Vpc_Endpoint"
            name="vpcEndpoint"
            rules={[{ required: true }]}
          />
          <ProFormText
            label="Obs_Endpoint"
            name="obsEndpoint"
            rules={[{ required: true }]}
          />
          <ProFormText
            label="RegionId"
            name="regionId"
            rules={[{ required: true }]}
          />
          <ProFormText label="ProjectId" name="projectId" />
        </>
      )}
    </>
  );
};

// New | Edit Cloud Account
const EditDrawerForm: React.FC<IEditFormProps> = (props) => {
  // Global Props
  const { platformList } = useModel('rule');
  const { tenantListAll } = useModel('tenant');
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Form Instance
  const [form] = Form.useForm<FormInstance>();
  // Intl API
  const intl = useIntl();

  const [jsonValue, setJsonValue] = useState('{}');

  const jsonEditorChangeCallback = (
    value: React.SetStateAction<string>,
  ): void => {
    setJsonValue(value);
    form.validateFields(['credentialsJson']);
  };

  // Component Props
  const {
    editFormVisible,
    accountInfo,
    setEditFormVisible,
    requestCurrentData,
  } = props;

  // Resource Type List Request Loading
  const [resourceListLoading, setResourceListLoading] =
    useState<boolean>(false);
  // List of Resource Types
  const [resourceTypeList, setResourceTypeList] = useState([]);
  // Edit Box
  const [extendEditorVisible, setExtendEditorVisible] = useState<boolean>(true);

  // New | Edit Cloud Account Submit
  const onClickFishEditForm = async (formData: any): Promise<void> => {
    const {
      cloudAccountId,
      alias,
      tenantId,
      platform,
      resourceTypeList,
      site,
      owner,
    } = formData || {};
    const postBody: API.CloudAccountResult = {
      cloudAccountId, // Cloud account ID
      alias, // Account aliases
      tenantId, // TenantId
      platform, // Cloud account Platform
      resourceTypeList, // Cloud service type
      site, // Cloud account site
      owner, // Owner
    };
    let credentialsObj: Record<string, any> = {};
    if (BASIC_EDITOR_LIST.includes(platform)) {
      credentialsObj = {
        ak: formData?.ak,
        sk: formData?.sk,
      };
    } else if (JSON_EDITOR_LIST.includes(platform)) {
      credentialsObj = {
        credential: jsonValue,
      };
    } else if (EXCLUSIVE_EDITOR_LIST.includes(platform)) {
      credentialsObj = {
        ak: formData?.ak,
        sk: formData?.sk,
        endpoint: formData?.endpoint,
        regionId: formData?.regionId,
      };
    } else if (EXTEND_EDITOR_LIST.includes(platform)) {
      credentialsObj = {
        ak: formData?.ak,
        sk: formData?.sk,
        iamEndpoint: formData?.iamEndpoint,
        ecsEndpoint: formData?.ecsEndpoint,
        elbEndpoint: formData?.elbEndpoint,
        evsEndpoint: formData?.evsEndpoint,
        vpcEndpoint: formData?.vpcEndpoint,
        obsEndpoint: formData?.obsEndpoint,
        regionId: formData?.regionId,
        projectId: formData?.projectId,
      };
    }
    postBody.credentialsObj = credentialsObj;
    if (accountInfo.id) postBody.id = accountInfo.id;
    const res: API.Result_String_ = await saveCloudAccount(postBody);
    if (res.msg === 'success') {
      if (accountInfo.id) {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.edit.success' }),
        );
      } else {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.create.success' }),
        );
      }
      setEditFormVisible(false);
      await requestCurrentData();
    }
  };

  // List of corresponding resource types requested based on platform selection
  const requestResourceList = async (platform: string): Promise<void> => {
    if (!platform?.trim()) return;
    setResourceListLoading(true);
    const res = await queryGroupTypeList({ platformList: [platform] });
    setResourceListLoading(false);
    if (isEmpty(res.content)) {
      setResourceTypeList([]);
      messageApi.error(
        intl.formatMessage({ id: 'cloudAccount.message.text.no.assets' }),
      );
    } else {
      setResourceTypeList(res?.content as any);
    }
  };

  const initDependencyVariable = (): void => {
    setExtendEditorVisible(false);
  };

  useEffect((): void => {
    if (editFormVisible && !isEmpty(accountInfo) && accountInfo.id) {
      initDependencyVariable();
      const { resourceTypeListForWeb, credentialMap, ...reset } = accountInfo;
      form.setFieldsValue({
        ...reset,
        ...credentialMap,
        resourceTypeList: resourceTypeListForWeb,
      });
      if (accountInfo.platform) requestResourceList(accountInfo.platform);
    }
  }, [editFormVisible, accountInfo]);

  const initForm = (): void => {
    form.resetFields();
    setExtendEditorVisible(true);
  };
  const onCancel = (): void => {
    setEditFormVisible(false);
    initForm();
  };

  return (
    <>
      {contextHolder}
      <DrawerForm
        labelCol={{
          span: 5,
        }}
        wrapperCol={{ span: 17 }}
        title={
          <>
            <span style={{ marginRight: 4 }}>
              {accountInfo.id
                ? intl.formatMessage({
                    id: 'cloudAccount.extend.title.edit',
                  })
                : intl.formatMessage({
                    id: 'cloudAccount.extend.title.add',
                  })}
            </span>
            <Button
              size={'small'}
              type={'link'}
              href={
                'https://cloudrec.yuque.com/org-wiki-cloudrec-iew3sz/hocvhx/fetbofdu8dx15q73'
              }
              target={'_blank'}
              style={{ color: '#2f54eb', gap: 4 }}
            >
              <ExportOutlined />
              <span>
                {intl.formatMessage({
                  id: 'common.link.text.help.center',
                })}
              </span>
            </Button>
          </>
        }
        width={720}
        form={form}
        drawerProps={{
          destroyOnClose: true,
          onClose: () => onCancel(),
          styles: {
            body: {
              paddingTop: 24,
            },
          },
        }}
        open={editFormVisible}
        onFinish={onClickFishEditForm}
        layout={'horizontal'}
      >
        <Divider style={{ marginTop: 0, marginBottom: 24 }} dashed>
          <Text italic>
            {intl.formatMessage({
              id: 'cloudAccount.extend.title.basic.information',
            })}
          </Text>
        </Divider>
        <Row>
          <Col span={24}>
            <ProFormText
              disabled={!!accountInfo.id}
              name="cloudAccountId"
              label={intl.formatMessage({
                id: 'cloudAccount.extend.title.account.id',
              })}
              rules={[{ required: true }]}
              placeholder="请输入云账号ID"
              fieldProps={{
                suffix: !!accountInfo.id && ( // disabled状态 提示信息
                  <Tooltip title="云账号ID为云平台主账号ID，创建后无法修改">
                    <InfoCircleOutlined style={{ color: 'rgba(0,0,0,.45)' }} />
                  </Tooltip>
                ),
              }}
            />
          </Col>
          <Col span={24}>
            <ProFormText
              name="alias"
              label={intl.formatMessage({
                id: 'cloudAccount.extend.title.account.alias',
              })}
              rules={[{ required: true }]}
              placeholder="请输入云账号别名"
            />
          </Col>
          <Col span={24}>
            <ProFormSelect
              label={intl.formatMessage({
                id: 'common.select.label.tenant',
              })}
              name={'tenantId'}
              placeholder="请选择租户"
              rules={[{ required: true }]}
              options={tenantListAll}
              disabled={accountInfo.id && !accountInfo?.changeTenantPermission}
            />
          </Col>
          <Col span={24}>
            <ProFormText
              name="owner"
              label="Owner"
              rules={[{ required: false }]}
            />
          </Col>
          <Col span={24}>
            <ProFormSelect
              label={intl.formatMessage({
                id: 'cloudAccount.extend.title.cloud.platform',
              })}
              name={'platform'}
              placeholder="请选择云平台"
              rules={[{ required: true, message: '请选择云平台' }]}
              options={(valueListAddIcon(platformList, 'start') as any) || []}
              onChange={(value: string) => {
                if (accountInfo.id) initDependencyVariable();
                // @ts-ignore
                form.setFieldValue('resourceTypeList', null);
                requestResourceList(value);
              }}
              formItemProps={{
                style: { marginBottom: 24 },
              }}
            />
          </Col>
        </Row>

        <ProFormDependency name={['platform']}>
          {({ platform }): JSX.Element => {
            if (isEmpty(platform)) return <></>;
            return (
              <Row>
                <Col span={24}>
                  <Divider style={{ marginTop: 0, marginBottom: 24 }} dashed>
                    <Text italic>
                      {intl.formatMessage({
                        id: 'cloudAccount.extend.title.detailed.configuration',
                      })}
                    </Text>
                  </Divider>
                  {JSON_EDITOR_LIST?.includes(platform) ? (
                    <JsonEditorModule
                      accountId={accountInfo.id}
                      extendEditorVisible={extendEditorVisible}
                      setExtendEditorVisible={setExtendEditorVisible}
                      jsonValue={jsonValue}
                      jsonEditorChangeCallback={jsonEditorChangeCallback}
                    />
                  ) : BASIC_EDITOR_LIST.includes(platform) ? (
                    <BasicEditorModule
                      accountId={accountInfo.id}
                      extendEditorVisible={extendEditorVisible}
                      setExtendEditorVisible={setExtendEditorVisible}
                    />
                  ) : EXCLUSIVE_EDITOR_LIST.includes(platform) ? (
                    <ExclusiveEditorModule
                      accountId={accountInfo.id}
                      extendEditorVisible={extendEditorVisible}
                      setExtendEditorVisible={setExtendEditorVisible}
                    />
                  ) : EXTEND_EDITOR_LIST.includes(platform) ? (
                    <ExtendEditorModule
                      accountId={accountInfo.id}
                      extendEditorVisible={extendEditorVisible}
                      setExtendEditorVisible={setExtendEditorVisible}
                    />
                  ) : (
                    <></>
                  )}
                </Col>
                <Col span={24}>
                  <ProFormCascader
                    label={intl.formatMessage({
                      id: 'cloudAccount.extend.title.cloud.services',
                    })}
                    name={'resourceTypeList'}
                    fieldProps={{
                      multiple: true,
                      showCheckedStrategy: SHOW_CHILD,
                      options: resourceTypeList || [],
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
                    label={intl.formatMessage({
                      id: 'cloudAccount.extend.title.cloud.site',
                    })}
                    rules={[{ required: false }]}
                  />
                </Col>
              </Row>
            );
          }}
        </ProFormDependency>
      </DrawerForm>
    </>
  );
};

export default EditDrawerForm;

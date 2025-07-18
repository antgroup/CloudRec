import CONFIG_ICON from '@/assets/images/CONFIG_ICON.svg';
import EVALUATE_ICON from '@/assets/images/EVALUATE_ICON.svg';
import RELATION from '@/assets/images/RELATION.svg';
import ConditionTag from '@/components/Common/ConditionTag';
import Disposition from '@/components/Disposition';
import { JSONEditor, JSONView, RegoEditor } from '@/components/Editor';
import LinkDrawerForm from '@/pages/RuleManagement/RuleProject/components/LinkDrawerForm';
import NoteDrawer from '@/pages/RuleManagement/RuleProject/components/NoteDrawer';
import VariableDrawer from '@/pages/RuleManagement/RuleProject/components/VariableDrawer';
import {
  CONTEXT_TEMPLATE,
  DEFAULT_CODE_EDITOR,
} from '@/pages/RuleManagement/RuleProject/const';
import { cloudAccountBaseInfoListV2 } from '@/services/account/AccountController';
import { evaluateRego } from '@/services/rego/RegoController';
import { queryGroupTypeList } from '@/services/resource/ResourceController';
import {
  queryAnalysisProgress,
  queryCancelTask,
  queryResourceExampleData,
  queryRuleDetail,
  saveRule,
} from '@/services/rule/RuleController';
import { RiskLevelList } from '@/utils/const';
import {
  obtainIntactRiskLevel,
  obtainLastElement,
  obtainPlatformIcon,
  obtainResourceTypeTextFromValue,
  obtainRuleTypeTextList,
  roundToN,
  valueListAddIcon,
  valueListAddTag,
} from '@/utils/shared';
import { useMediaQuerySize } from '@/utils/useMediaQuery';
import { ArrowLeftOutlined } from '@ant-design/icons';
import {
  PageContainer,
  ProCard,
  ProFormDependency,
  ProFormInstance,
  ProFormRadio,
  ProFormText,
  ProFormTextArea,
} from '@ant-design/pro-components';
import {
  FormattedMessage,
  history,
  useIntl,
  useLocation,
  useModel,
  useRequest,
} from '@umijs/max';
import {
  Button,
  Cascader,
  Col,
  Flex,
  FloatButton,
  Form,
  Input,
  message,
  Modal,
  Popover,
  Progress,
  Radio,
  RadioChangeEvent,
  Row,
  Select,
  Space,
  Steps,
  Tooltip,
  Typography,
} from 'antd';
import { debounce, isEmpty } from 'lodash';
import React, { useEffect, useRef, useState } from 'react';
import styles from '../index.less';

const { Title } = Typography;
const { SHOW_CHILD } = Cascader;

const EVALUATE_TYPE_LIST = [
  {
    label: <FormattedMessage id={'rule.module.text.example.data'} />,
    value: 'INPUT',
  },
  {
    label: <FormattedMessage id={'rule.module.text.appoint.tenant'} />,
    value: 'TENANT',
  },
  {
    label: <FormattedMessage id={'rule.module.text.appoint.cloud.platform'} />,
    value: 'CLOUD_ACCOUNT',
  },
];

// Execute: Default Execution Progress
const INIT_ANALYSIS_PROGRESS = 0;

// New | Edit Rules.md
const EditPage: React.FC = () => {
  const { tenantListAdded } = useModel('tenant');
  // Get routing parameters
  const location = useLocation();
  const queryParameters: URLSearchParams = new URLSearchParams(location.search);
  const [id] = useState(queryParameters.get('id'));
  // Obtain the corresponding size based on the current screen width
  const mediaSize = useMediaQuerySize({});
  // Platform Rule Group List
  const { platformList, ruleGroupList, ruleTypeList } = useModel('rule');
  // Form Instance
  const [form] = Form.useForm();
  // Intl API
  const intl = useIntl();
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Modal API
  const [modal, modalContextHolder] = Modal.useModal();
  // Submit Loading
  const [submitLoading, setSubmitLoading] = useState<boolean>(false);
  // Rule Details Data
  const [ruleDetail, setRuleDetail] = useState({});
  // List of Resource Types
  const [resourceTypeList, setResourceTypeList] = useState([]);
  // Code Editor(Rego)
  const [codeEditor, setCodeEditor] = useState(DEFAULT_CODE_EDITOR);
  // Input
  const [inputEditor, setInputEditor] = useState(``);
  // Output
  const [outputEditor, setOutputEditor] = useState<Record<string, any>>({});
  // History
  const [noteDrawerVisible, setNoteDrawerVisible] = useState<boolean>(false);
  // Rule Information
  const noteDrawerInfo = useRef<Record<string, any>>({});
  // History
  const [variableDrawerVisible, setVariableDrawerVisible] =
    useState<boolean>(false);
  // Rule Information
  const variableDrawerInfo = useRef<Record<string, any>>({});
  // Currently selected row
  const [selectedRowKeys, setSelectedRowKeys] = useState<any[]>([]);
  // Form data
  const [formData, setFormData] = useState<Record<string, any>>({});
  // Results of execution
  const evaluateResultRef = useRef<string>(`waiting`);
  // Details page loading
  const [ruleDetailLoading, setRuleDetailLoading] = useState<boolean>(false);
  // Related assets
  const [linkDrawerVisible, setLinkDrawerVisible] = useState<boolean>(false);
  // ProForm Instance
  const linkFormRef = useRef<ProFormInstance<any>>();
  // Evaluate  Analysis Progress
  const [analysisProgress, setAnalysisProgress] = useState<number>(
    INIT_ANALYSIS_PROGRESS,
  );
  // Time Poll Timer
  const intervalTimer = useRef<any>(null);
  // Evaluate Rego Loading
  const [evaluateRegoLoading, setEvaluateRegoLoading] =
    useState<boolean>(false);

  // History
  const onClickHistoryMenu = (): void => {
    noteDrawerInfo.current = {
      ruleId: id,
    };
    setNoteDrawerVisible(true);
  };
  // Variable
  const onClickVariableMenu = (): void => {
    variableDrawerInfo.current = {
      ...ruleDetail,
    };
    setVariableDrawerVisible(true);
  };
  // Rego Encoding
  const onRegoEditorChange = (value: string): void => {
    setCodeEditor(value);
    // Rego rule modification requires re execution of detection
    evaluateResultRef.current = ``;
    // eslint-disable-next-line
    formatStepList(formData);
  };
  // Input value
  const onInputEditorChange = (value: string): void => {
    setInputEditor(value);
  };

  // According to the cloud platform, obtain a list of resource types
  const { run: requestResourceTypeList } = useRequest(
    (value: string) => {
      return queryGroupTypeList({ platformList: [value] });
    },
    {
      manual: true,
      formatResult: (result) => {
        const { content } = result;
        setResourceTypeList((content as any) || []);
        return content;
      },
    },
  );

  // Rule details INPUT (query based on cloud platform and resource type)
  const {
    run: requestResourceExampleData,
    loading: resourceExampleDataLoading,
  } = useRequest(
    (values) => {
      return queryResourceExampleData(values);
    },
    {
      formatResult: (result): void => {
        if (result.msg === 'success') {
          const { content } = result;
          try {
            setInputEditor(JSON.stringify(content, null, 4) || '');
          } catch (e) {
            console.info('Error', e);
          }
        }
      },
      manual: true,
    },
  );
  // StepList
  const [stepList, setStepList] = useState([
    {
      title: <FormattedMessage id={'rule.module.text.basic.info'} />,
      description: <></>,
    },
    {
      title: <FormattedMessage id={'rule.module.text.rule.development'} />,
      description: <></>,
    },
    {
      title: (
        <FormattedMessage id={'rule.module.text.repair.suggestions.title'} />
      ),
      description: <></>,
    },
  ]);
  // Current step
  const [current, setCurrent] = useState<number>(0);

  // Format StepList
  const formatStepList = (
    values: Record<string, any>,
    resourceTypeArray?: Array<any>,
  ): void => {
    const array = stepList.map((item, index) => {
      if (index === 0) {
        return {
          ...item,
          description: (
            <Popover
              content={
                <div style={{ padding: '2px 6px' }}>
                  <Flex style={{ marginBottom: 7 }}>
                    <span style={{ color: 'rgb(168, 168, 168)' }}>
                      {intl.formatMessage({
                        id: 'common.select.label.cloudPlatform',
                      })}
                      &nbsp;:&nbsp;
                    </span>
                    <span style={{ color: 'rgb(48, 48, 48)' }}>
                      {obtainPlatformIcon(values?.platform, platformList)}
                    </span>
                  </Flex>
                  <Flex style={{ margin: '7px 0' }}>
                    <span style={{ color: 'rgb(168, 168, 168)' }}>
                      {intl.formatMessage({
                        id: 'cloudAccount.extend.title.asset.type',
                      })}
                      &nbsp;:&nbsp;
                    </span>
                    <span style={{ color: 'rgb(48, 48, 48)' }}>
                      {obtainResourceTypeTextFromValue(
                        resourceTypeArray || resourceTypeList,
                        values?.resourceType,
                      ) || '-'}
                    </span>
                  </Flex>
                  <Flex style={{ margin: '7px 0' }}>
                    <span
                      style={{ flexShrink: 0, color: 'rgb(168, 168, 168)' }}
                    >
                      {intl.formatMessage({
                        id: 'home.module.inform.columns.ruleName',
                      })}
                      &nbsp;:&nbsp;
                    </span>
                    <Disposition
                      text={values?.ruleName || '-'}
                      maxWidth={240}
                      rows={1}
                      color={'rgb(48, 48, 48)'}
                    />
                  </Flex>
                  <Flex style={{ margin: '7px 0' }}>
                    <span
                      style={{ flexShrink: 0, color: 'rgb(168, 168, 168)' }}
                    >
                      {intl.formatMessage({
                        id: 'rule.module.text.rule.describe',
                      })}
                      &nbsp;:&nbsp;
                    </span>
                    <Disposition
                      text={values?.ruleDesc || '-'}
                      maxWidth={240}
                      rows={1}
                      color={'rgb(48, 48, 48)'}
                    />
                  </Flex>
                  <Flex style={{ margin: '7px 0' }}>
                    <span style={{ color: 'rgb(168, 168, 168)' }}>
                      {intl.formatMessage({
                        id: 'layout.routes.title.ruleGroup',
                      })}
                      &nbsp;:&nbsp;
                    </span>
                    <Disposition
                      text={
                        ruleGroupList
                          ?.filter((i: any) =>
                            values?.ruleGroupIdList?.includes(i?.value),
                          )
                          .map((j: any) => j?.label)
                          ?.toString() || '-'
                      }
                      maxWidth={100}
                      rows={1}
                      color={'rgb(48, 48, 48)'}
                    />
                  </Flex>
                  <Flex style={{ margin: '7px 0' }}>
                    <span
                      style={{ flexShrink: 0, color: 'rgb(168, 168, 168)' }}
                    >
                      {intl.formatMessage({
                        id: 'home.module.inform.columns.ruleTypeName',
                      })}
                      &nbsp;:&nbsp;
                    </span>
                    <Disposition
                      text={
                        obtainRuleTypeTextList(
                          ruleTypeList,
                          values?.ruleTypeIdList,
                        ) || '-'
                      }
                      maxWidth={240}
                      rows={1}
                      color={'rgb(48, 48, 48)'}
                    />
                  </Flex>
                  <Flex style={{ marginTop: 7 }} align={'center'}>
                    <span style={{ color: 'rgb(168, 168, 168)' }}>
                      {intl.formatMessage({
                        id: 'home.module.inform.columns.riskLevel',
                      })}
                      &nbsp;:&nbsp;
                    </span>
                    {obtainIntactRiskLevel(RiskLevelList, values.riskLevel)}
                  </Flex>
                </div>
              }
            >
              <Flex style={{ margin: '6px 0' }}>
                <span style={{ color: 'rgb(168, 168, 168)' }}>
                  {intl.formatMessage({
                    id: 'common.table.columns.platform',
                  })}
                  &nbsp;:&nbsp;
                </span>
                <span style={{ color: 'rgb(48, 48, 48)' }}>
                  {obtainPlatformIcon(values?.platform, platformList)}
                </span>
              </Flex>
            </Popover>
          ),
        };
      } else if (index === 1) {
        return {
          ...item,
          description: (
            <div>
              {evaluateResultRef.current && (
                <Flex style={{ marginTop: 6 }} align={'center'}>
                  <span style={{ flexShrink: 0, color: 'rgb(168, 168, 168)' }}>
                    {intl.formatMessage({
                      id: 'rule.module.text.running.results',
                    })}
                    &nbsp;:&nbsp;
                  </span>
                  <ConditionTag state={evaluateResultRef.current as any} />
                </Flex>
              )}
            </div>
          ),
        };
      } else if (index === 2) {
        return {
          ...item,
          description: (
            <Popover
              placement={'bottom'}
              content={
                <div style={{ padding: '2px 6px' }}>
                  <Flex style={{ marginBottom: 7 }}>
                    <span
                      style={{ flexShrink: 0, color: 'rgb(168, 168, 168)' }}
                    >
                      {intl.formatMessage({
                        id: 'rule.module.text.repair.suggestions',
                      })}
                      &nbsp;:&nbsp;
                    </span>
                    <Disposition
                      text={values?.advice || '-'}
                      maxWidth={240}
                      rows={1}
                      color={'rgb(48, 48, 48)'}
                    />
                  </Flex>
                  <Flex style={{ margin: '7px 0' }}>
                    <span
                      style={{ flexShrink: 0, color: 'rgb(168, 168, 168)' }}
                    >
                      {intl.formatMessage({
                        id: 'rule.module.text.reference.link',
                      })}
                      &nbsp;:&nbsp;
                    </span>
                    <Disposition
                      text={values?.link || '-'}
                      maxWidth={240}
                      rows={1}
                      color={'rgb(48, 48, 48)'}
                    />
                  </Flex>
                  <Flex style={{ margin: '7px 0' }}>
                    <span
                      style={{ flexShrink: 0, color: 'rgb(168, 168, 168)' }}
                    >
                      {intl.formatMessage({
                        id: 'rule.module.text.risk.context.template',
                      })}
                      &nbsp;:&nbsp;
                    </span>
                    <Disposition
                      text={values?.context || '-'}
                      maxWidth={240}
                      rows={1}
                      color={'rgb(48, 48, 48)'}
                    />
                  </Flex>
                </div>
              }
            >
              <Flex style={{ margin: '6px 0' }}>
                <span style={{ flexShrink: 0, color: 'rgb(168, 168, 168)' }}>
                  {intl.formatMessage({
                    id: 'rule.module.text.repair.suggestions',
                  })}
                  &nbsp;:&nbsp;
                </span>
                <Disposition
                  text={values?.advice || '-'}
                  maxWidth={180}
                  rows={1}
                  color={
                    current === 2
                      ? 'rgba(0, 0, 0, 0.88)'
                      : 'rgba(0, 0, 0, 0.45)'
                  }
                />
              </Flex>
            </Popover>
          ),
        };
      } else {
        return {
          ...item,
        };
      }
    });
    setStepList(array);
  };

  // Query Analysis Progress
  const { run: requestAnalysisProgress } = useRequest(
    (taskId: number) => {
      return queryAnalysisProgress({ taskId });
    },
    {
      formatResult: (r): number => {
        if (r?.content?.percent === 1) {
          evaluateResultRef.current = 'success';
          setOutputEditor(JSON.parse(r?.content?.result) || {});
          formatStepList(formData);
        }
        return r?.content?.percent;
      },
      onSuccess: (data): void => {
        setAnalysisProgress(data);
      },
      manual: true,
    },
  );

  // Query Cancel Analysis Task
  const { run: requestCancelTask } = useRequest(
    (taskId: number) => {
      return queryCancelTask({ taskId });
    },
    {
      onSuccess: () =>
        messageApi.warning(
          intl.formatMessage({ id: 'rule.message.text.task.cancelled' }),
        ),
      manual: true,
    },
  );

  // Tenant || Cloud Account
  const analysis = (taskId: number): void => {
    const instance = modal.info({
      title: intl.formatMessage({ id: 'common.message.text.execute.loading' }),
      content: (
        <Flex style={{ width: '100' }} justify={'center'}>
          <Progress
            type="circle"
            percent={Number(roundToN(analysisProgress * 100, 2))}
            size={80}
          />
        </Flex>
      ),
      closable: true,
      destroyOnClose: true,
      footer: <></>,
      onCancel: (): void => {
        if (intervalTimer.current) clearTimeout(intervalTimer.current);
        requestCancelTask(taskId);
      },
    });

    intervalTimer.current = setInterval(async (): Promise<void> => {
      const data: number = await requestAnalysisProgress(taskId);
      instance.update({
        title: intl.formatMessage({
          id: 'common.message.text.execute.loading',
        }),
        content: (
          <Flex style={{ width: '100' }} justify={'center'}>
            <Progress
              type="circle"
              percent={Number(roundToN(data * 100, 2))}
              size={80}
            />
          </Flex>
        ),
        closable: true,
        destroyOnClose: true,
        footer: <></>,
        onCancel: (): void => {
          if (intervalTimer.current) clearTimeout(intervalTimer.current);
          requestCancelTask(taskId);
        },
      });
      if (data === 1) {
        clearInterval(intervalTimer.current);
        const timeoutTimer = setTimeout((): void => {
          clearTimeout(timeoutTimer);
          setAnalysisProgress(INIT_ANALYSIS_PROGRESS);
          instance.destroy();
        }, 800);
      }
    }, 1000);
  };

  // Execute
  const onClickEvaluate = async (): Promise<any> => {
    const postBody: Record<string, any> = {};
    const type = form.getFieldValue('type');
    if (type === EVALUATE_TYPE_LIST[0].value) {
      postBody.ruleRego = codeEditor;
      postBody.input = inputEditor;
      postBody.globalVariableConfigIdList = selectedRowKeys;
      postBody.linkedDataList = formData?.linkedDataList || [];
    } else {
      // Tenant ||  Cloud Account
      postBody.type = type;
      const selectId = form.getFieldValue('selectId');
      postBody.selectId = selectId;
      postBody.ruleRego = codeEditor;
      postBody.platform = form.getFieldValue('platform');
      postBody.resourceType = obtainLastElement(
        form.getFieldValue('resourceType'),
      );
      postBody.linkedDataList = formData?.linkedDataList || [];
      if (type === EVALUATE_TYPE_LIST[1].value && !selectId) {
        return messageApi.error(`请选择${EVALUATE_TYPE_LIST[1].label}`);
      } else if (type === EVALUATE_TYPE_LIST[2].value && !selectId) {
        return messageApi.error(`请选择${EVALUATE_TYPE_LIST[2].label}`);
      }
    }
    setEvaluateRegoLoading(true);
    const res: API.Result_T_ = await evaluateRego(postBody);
    setEvaluateRegoLoading(false);
    if (type === EVALUATE_TYPE_LIST[0].value) {
      if (res.code === 200 && res.msg === 'success') {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.execute.success' }),
        );
        setOutputEditor(res?.content?.result || {});
        evaluateResultRef.current = 'success';
        formatStepList(formData);
      } else if (res.code !== 200 || res.msg !== 'success') {
        // Analysis failed, display the reason for the failure
        setOutputEditor(res || {});
        evaluateResultRef.current = 'error';
        formatStepList(formData);
      }
    } else {
      if (res?.content?.taskId) analysis(res.content.taskId);
    }
  };

  // When updating Form data
  const handleFormValueChange = (changedValues: any, allValues: any): void => {
    setFormData({
      ...formData,
      ...allValues,
    });
    formatStepList({
      ...formData,
      ...allValues,
    });
  };
  // Previous step
  const onClickPreStep = (): void => {
    setCurrent((current: number) => current - 1);
  };
  // Next step
  const onClickNextStep = (): any => {
    form.validateFields().then(async (values): Promise<any> => {
      if (current === 0) {
        await requestResourceExampleData({
          platform: values?.platform,
          resourceType: values?.resourceType,
          linkedDataList: values?.linkedDataList || [],
        });
      } else if (current === 1) {
        if (isEmpty(codeEditor)) {
          return messageApi.error(
            intl.formatMessage({ id: 'rule.message.text.rego.noEmpty' }),
          );
        }
        // Determine whether the Rego rule has been executed successfully
        if (evaluateResultRef.current !== 'success') {
          return messageApi.error(
            intl.formatMessage({ id: 'rule.message.text.rego.noPass' }),
          );
        }
      }
      setCurrent((current: number) => current + 1);
    });
  };

  useEffect((): void => {
    // Reformat stepList when modifying steps
    if (!isEmpty(formData)) formatStepList(formData);
  }, [current]);

  // submit
  const onClickSubmitForm = (): void => {
    form.validateFields().then(async (value): Promise<void> => {
      setSubmitLoading(true);
      const postBody: any = {
        ...formData,
        ruleRego: codeEditor,
        globalVariableConfigIdList: selectedRowKeys,
        context: value?.context,
      };
      if (id) postBody.id = id;
      delete postBody?.type;
      delete postBody?.selectId;
      delete postBody?.ruleGroupList;
      const res: API.Result_String_ = await saveRule(postBody);
      setSubmitLoading(false);
      if (res.msg === 'success' || [200].includes(res.code!)) {
        if (id) {
          messageApi.success(
            intl.formatMessage({ id: 'common.message.text.edit.success' }),
          );
        } else {
          messageApi.success(
            intl.formatMessage({ id: 'common.message.text.create.success' }),
          );
        }
        history.push('/ruleManagement/ruleProject?tab=market');
      }
    });
  };

  // Form form data assignment
  const assignForm = async (values: Record<string, any>): Promise<void> => {
    if (!isEmpty(values)) {
      // Batch add variable idList
      setSelectedRowKeys(values?.globalVariableConfigIdList || []);
      // Set the current step as the first step (step value: default starting from 0)
      setCurrent(0);
      evaluateResultRef.current = 'success';
      const formatValue = {
        ...values,
        ruleGroupIdList: values?.ruleGroupList?.map((item: any) => item?.id),
      };
      setFormData(formatValue);
      form.setFieldsValue(formatValue);
      setCodeEditor(values?.ruleRego || '');
      if (values?.platform) {
        requestResourceTypeList(values?.platform)
          .then((array): void => {
            formatStepList(formatValue, array);
          })
          .finally(() => setRuleDetailLoading(false));
      }
    }
  };

  // Rule details inquiry
  const { run: requestRuleDetailById } = useRequest(
    async (id: number | string) => {
      return await queryRuleDetail({ id: Number(id) });
    },
    {
      formatResult: async (result): Promise<void> => {
        const { content } = result;
        setRuleDetail(content);
        await assignForm(content);
      },
      manual: true,
    },
  );

  // Request details of relevant rules (edit rules)
  useEffect((): void => {
    if (id) {
      setRuleDetailLoading(true);
      requestRuleDetailById(id);
    }
  }, [id]);

  const onClickLinkAsset = (): void => {
    setLinkDrawerVisible(true);
  };

  // Cloud account list data
  const { data: baseCloudAccountList, run: requestCloudAccountBaseInfoList } =
    useRequest(
      (params: { cloudAccountSearch?: string; platformList?: string[] }) => {
        return cloudAccountBaseInfoListV2({ ...params });
      },
      {
        manual: true,
        formatResult: (r) => r?.content,
      },
    );

  // Cloud account list filtering
  const debounceFetcher = debounce((fuzzy?: string): void => {
    const platform = form.getFieldValue('platform');
    const platformList: any[] = [];
    if (platform) platformList.push(platform);
    requestCloudAccountBaseInfoList({
      platformList: platformList,
      cloudAccountSearch: fuzzy,
    });
  }, 500);

  return (
    <PageContainer
      ghost={true}
      breadcrumbRender={false}
      header={{
        ghost: true,
      }}
      title={
        <Button type={'link'} size={'small'} onClick={() => history?.back()}>
          <ArrowLeftOutlined />
          {intl.formatMessage({
            id: 'common.button.text.return',
          })}
        </Button>
      }
      className={
        current === 1
          ? styles['ruleEditPageContainerSpecial']
          : styles['ruleEditPageContainer']
      }
      footer={[
        <Space key={'buttonList'} style={{ paddingRight: 8 }}>
          {current > 0 && (
            <Button type="primary" onClick={() => onClickPreStep()}>
              {intl.formatMessage({
                id: 'common.button.text.pre',
              })}
            </Button>
          )}
          {current < stepList.length - 1 && (
            <Button
              type="primary"
              onClick={() => onClickNextStep()}
              loading={resourceExampleDataLoading}
            >
              {intl.formatMessage({
                id: 'common.button.text.next',
              })}
            </Button>
          )}
          {current === stepList.length - 1 && (
            <Button
              loading={submitLoading}
              type="primary"
              onClick={() => onClickSubmitForm()}
            >
              {intl.formatMessage({
                id: 'common.button.text.submit',
              })}
            </Button>
          )}
        </Space>,
      ]}
      loading={ruleDetailLoading}
    >
      {contextHolder}
      {modalContextHolder}
      <Row
        style={{
          marginBottom: 20,
          padding: current === 1 ? '0 14px' : 'unset',
        }}
      >
        <Col span={24} style={{ minHeight: '100%' }}>
          <ProCard className={styles['stepListMain']}>
            <Steps
              size={'small'}
              className={styles['stepsWrap']}
              direction={'horizontal'}
              current={current}
              items={stepList}
            />
          </ProCard>
        </Col>
      </Row>
      <Row style={{ minHeight: 'calc(100vh - 362px)' }}>
        <Col span={24} style={{ minHeight: '100%' }}>
          <ProCard
            className={
              current === 1
                ? styles['contentMainTransparent']
                : styles['contentMain']
            }
            bodyStyle={{ paddingTop: current === 1 ? 0 : 16 }}
          >
            <Form
              form={form}
              layout={'vertical'}
              onValuesChange={debounce(handleFormValueChange, 200)}
            >
              {current === 0 && (
                <>
                  <Form.Item
                    name="platform"
                    label={intl.formatMessage({
                      id: 'home.module.overview.platform',
                    })}
                    rules={[
                      {
                        required: true,
                        message: intl.formatMessage({
                          id: 'common.select.text.placeholder',
                        }),
                      },
                    ]}
                  >
                    <Radio.Group
                      disabled={!!id}
                      onChange={(e: RadioChangeEvent): void => {
                        form.setFieldValue('resourceType', null);
                        form.setFieldValue('linkedDataList', []);
                        setFormData({
                          ...formData,
                          linkedDataList: null,
                        });
                        setResourceTypeList([]);
                        requestResourceTypeList(e.target.value);
                      }}
                      options={valueListAddIcon(platformList)}
                    />
                  </Form.Item>

                  <ProFormDependency name={['platform']}>
                    {({ platform }) => {
                      if (isEmpty(platform)) return <></>;
                      return (
                        <Form.Item
                          name="resourceType"
                          label={intl.formatMessage({
                            id: 'cloudAccount.extend.title.asset.type',
                          })}
                          rules={[
                            {
                              required: true,
                              message: intl.formatMessage({
                                id: 'common.select.text.placeholder',
                              }),
                            },
                          ]}
                          style={{
                            marginBottom: 0,
                          }}
                        >
                          <Cascader
                            // disabled={!!id}
                            options={resourceTypeList}
                            multiple={false}
                            placeholder={intl.formatMessage({
                              id: 'common.select.text.placeholder',
                            })}
                            showCheckedStrategy={SHOW_CHILD}
                            allowClear
                            showSearch
                          />
                        </Form.Item>
                      );
                    }}
                  </ProFormDependency>

                  <ProFormDependency name={['platform']}>
                    {({ platform }) => {
                      if (isEmpty(platform)) return <></>;
                      return (
                        <Form.Item
                          layout={'horizontal'}
                          name="linkedDataList"
                          label=""
                          style={{
                            marginBottom: 24,
                          }}
                        >
                          <Button
                            type={'link'}
                            size={'small'}
                            onClick={() => onClickLinkAsset()}
                            style={{ gap: 4 }}
                          >
                            <img
                              src={RELATION}
                              alt="RELATION_ICON"
                              style={{ width: 14, height: 14 }}
                            />
                            {intl.formatMessage({
                              id: 'rule.module.text.related.assets',
                            })}
                          </Button>
                          {formData?.linkedDataDesc && (
                            <Space size={[8, 16]} wrap>
                              <span style={{ color: '#c5c2c2' }}>
                                {formData?.linkedDataDesc}
                              </span>
                            </Space>
                          )}
                        </Form.Item>
                      );
                    }}
                  </ProFormDependency>

                  <Row gutter={[24, 12]}>
                    <Col span={12}>
                      <Form.Item
                        name="ruleName"
                        label={intl.formatMessage({
                          id: 'home.module.inform.columns.ruleName',
                        })}
                        rules={[{ required: true }]}
                      >
                        <Input
                          placeholder={intl.formatMessage({
                            id: 'common.input.text.placeholder',
                          })}
                        />
                      </Form.Item>
                    </Col>
                    <Col span={12}>
                      <Form.Item
                        name="ruleDesc"
                        label={intl.formatMessage({
                          id: 'rule.module.text.rule.describe',
                        })}
                        rules={[{ required: true }]}
                      >
                        <Input
                          placeholder={intl.formatMessage({
                            id: 'common.input.text.placeholder',
                          })}
                        />
                      </Form.Item>
                    </Col>
                    <Col span={12}>
                      <Form.Item
                        name="ruleGroupIdList"
                        label={intl.formatMessage({
                          id: 'layout.routes.title.ruleGroup',
                        })}
                        rules={[
                          {
                            required: false,
                            message: intl.formatMessage({
                              id: 'common.select.text.placeholder',
                            }),
                          },
                        ]}
                      >
                        <Select
                          options={ruleGroupList || []}
                          placeholder={intl.formatMessage({
                            id: 'common.select.text.placeholder',
                          })}
                          allowClear
                          mode={'multiple'}
                        />
                      </Form.Item>
                    </Col>
                    <Col span={12}>
                      <Form.Item
                        label={intl.formatMessage({
                          id: 'home.module.inform.columns.ruleTypeName',
                        })}
                        name={'ruleTypeIdList'}
                        rules={[
                          {
                            required: true,
                            message: intl.formatMessage({
                              id: 'common.select.text.placeholder',
                            }),
                          },
                        ]}
                      >
                        <Cascader
                          showCheckedStrategy={SHOW_CHILD}
                          allowClear
                          showSearch
                          fieldNames={{
                            label: 'typeName',
                            value: 'id',
                            children: 'childList',
                          }}
                          multiple
                          options={ruleTypeList || []}
                        />
                      </Form.Item>
                    </Col>
                    <Col span={12}>
                      <ProFormRadio.Group
                        name="riskLevel"
                        label={intl.formatMessage({
                          id: 'home.module.inform.columns.riskLevel',
                        })}
                        rules={[
                          {
                            required: true,
                            message: intl.formatMessage({
                              id: 'common.select.text.placeholder',
                            }),
                          },
                        ]}
                        options={valueListAddTag(RiskLevelList)}
                        // formItemProps={{ style: { marginTop: 12 } }}
                      />
                    </Col>
                  </Row>
                </>
              )}
              {current === 1 && (
                <div>
                  <Row>
                    <Flex justify={'end'} style={{ width: '100%' }}>
                      <Space>
                        <Button
                          href={
                            'https://cloudrec.yuque.com/org-wiki-cloudrec-iew3sz/hocvhx/un0z2rchy084tnww'
                          }
                          target={'_blank'}
                          style={{
                            gap: 4,
                            border: '1px solid #457aff',
                            color: '#457aff',
                            padding: '4px 10px',
                            backgroundColor: 'transparent',
                          }}
                        >
                          <img
                            src={CONFIG_ICON}
                            style={{ height: 14 }}
                            alt="LINK_ICON"
                          />
                          {intl.formatMessage({
                            id: 'rule.extend.text.config',
                          })}
                        </Button>
                        <Button
                          type={'primary'}
                          onClick={() => onClickEvaluate()}
                          style={{ gap: 4 }}
                          loading={evaluateRegoLoading}
                        >
                          <img
                            src={EVALUATE_ICON}
                            style={{ height: 14 }}
                            alt={'linkIcon'}
                          />
                          {intl.formatMessage({
                            id: 'rule.extend.text.execute',
                          })}
                        </Button>
                      </Space>
                    </Flex>
                  </Row>
                  <Row gutter={16} style={{ marginTop: 4 }}>
                    <Col md={14} span={24}>
                      <Title
                        level={5}
                        className={styles['customTitle']}
                        style={{ marginBottom: 16 }}
                      >
                        The Rego PlayGround
                      </Title>
                      <RegoEditor
                        editorKey="regoEditor"
                        value={codeEditor}
                        onChange={onRegoEditorChange}
                        editorStyle={{ height: '680px' }}
                      />
                    </Col>

                    <Col md={10} span={24}>
                      <Title level={5} className={styles['customTitle']}>
                        <Flex align={'center'}>
                          <span style={{ marginRight: 12 }}>INPUT</span>
                          <Space.Compact>
                            <Form.Item
                              name={'type'}
                              noStyle
                              initialValue={EVALUATE_TYPE_LIST[0].value}
                            >
                              <Select
                                options={EVALUATE_TYPE_LIST}
                                style={{ width: 114 }}
                                onChange={(value): void => {
                                  form.setFieldValue('selectId', null);
                                  if (value === EVALUATE_TYPE_LIST[2].value)
                                    debounceFetcher();
                                }}
                              />
                            </Form.Item>
                            <ProFormDependency name={['type']}>
                              {({ type }) => {
                                let element = <></>;
                                if (type === EVALUATE_TYPE_LIST[1].value) {
                                  element = (
                                    <Form.Item noStyle name={'selectId'}>
                                      <Select
                                        options={tenantListAdded || []}
                                        style={{ width: 160 }}
                                        fieldNames={{
                                          label: 'tenantName',
                                          value: 'id',
                                        }}
                                      />
                                    </Form.Item>
                                  );
                                } else if (
                                  type === EVALUATE_TYPE_LIST[2].value
                                ) {
                                  element = (
                                    <Form.Item name="selectId" noStyle>
                                      <Select
                                        allowClear
                                        showSearch
                                        filterOption={false}
                                        placeholder={intl.formatMessage({
                                          id: 'common.select.query.text.placeholder',
                                        })}
                                        onSearch={debounceFetcher}
                                        options={
                                          baseCloudAccountList?.map(
                                            (item: Record<string, any>) => ({
                                              label: (
                                                <Tooltip
                                                  placement={'topLeft'}
                                                  title={
                                                    <>
                                                      <div>{item?.alias}</div>
                                                      <div>
                                                        {item?.cloudAccountId}
                                                      </div>
                                                    </>
                                                  }
                                                >
                                                  {item?.alias +
                                                    '/' +
                                                    item?.cloudAccountId}
                                                </Tooltip>
                                              ),
                                              value: item?.cloudAccountId,
                                            }),
                                          ) || []
                                        }
                                        style={{ width: 160 }}
                                      />
                                    </Form.Item>
                                  );
                                }
                                return element;
                              }}
                            </ProFormDependency>
                          </Space.Compact>
                        </Flex>
                      </Title>
                      <JSONEditor
                        editorStyle={{ height: '360px' }}
                        editorKey="inputEditor"
                        value={inputEditor}
                        onChange={onInputEditorChange}
                      />
                      <Title
                        style={{ marginTop: 8 }}
                        level={5}
                        className={styles['customTitle']}
                      >
                        OUTPUT
                      </Title>
                      <JSONView
                        viewerStyle={{ height: '280px' }}
                        value={outputEditor}
                      />
                    </Col>
                  </Row>
                </div>
              )}
              {current === 2 && (
                <>
                  <ProFormTextArea
                    name="advice"
                    label={intl.formatMessage({
                      id: 'rule.module.text.repair.suggestions',
                    })}
                    placeholder={intl.formatMessage({
                      id: 'common.input.text.placeholder',
                    })}
                  />
                  <ProFormText
                    name="link"
                    label={intl.formatMessage({
                      id: 'rule.module.text.reference.link',
                    })}
                    placeholder={intl.formatMessage({
                      id: 'common.input.text.placeholder',
                    })}
                    rules={[
                      {
                        pattern: new RegExp(
                          '^(https?|ftp):\\/\\/[^\\s/$.?#].[^\\s]*$',
                          'i',
                        ),
                        message: intl.formatMessage({
                          id: 'common.input.text.link.check',
                        }),
                      },
                    ]}
                  />
                  <ProFormTextArea
                    name="context"
                    label={intl.formatMessage({
                      id: 'rule.module.text.risk.context.template',
                    })}
                    placeholder={CONTEXT_TEMPLATE}
                  />
                </>
              )}
            </Form>
          </ProCard>
        </Col>
      </Row>

      {current === 1 && (
        <>
          <FloatButton.Group
            shape="square"
            style={{
              insetInlineEnd: -2,
              top: !['xxLProMax', 'xxLFullHD', 'xxLPro']?.includes(mediaSize)
                ? '36vh'
                : '7vh',
              boxShadow: 'none',
            }}
          >
            <FloatButton
              onClick={(): void => onClickHistoryMenu()}
              className={styles['floatButton']}
              icon={
                <div style={{ fontSize: 14 }}>
                  {intl.formatMessage({
                    id: 'rule.extend.text.history',
                  })}
                </div>
              }
            />
            <FloatButton
              onClick={(): void => onClickVariableMenu()}
              className={styles['floatButton']}
              icon={
                <div style={{ fontSize: 14 }}>
                  {intl.formatMessage({
                    id: 'rule.extend.text.variable',
                  })}
                </div>
              }
            />
          </FloatButton.Group>
        </>
      )}

      <NoteDrawer // Historical Version
        noteDrawerVisible={noteDrawerVisible}
        setNoteDrawerVisible={setNoteDrawerVisible}
        noteDrawerInfo={noteDrawerInfo.current}
        requestRuleDetailById={requestRuleDetailById}
      />

      <VariableDrawer // Variable
        formData={formData}
        setCurrent={setCurrent}
        variableDrawerVisible={variableDrawerVisible}
        setVariableDrawerVisible={setVariableDrawerVisible}
        variableDrawerInfo={variableDrawerInfo.current}
        requestRuleDetailById={requestRuleDetailById}
        selectedRowKeys={selectedRowKeys}
        setSelectedRowKeys={setSelectedRowKeys}
      />

      <LinkDrawerForm // Related assets
        linkDrawerVisible={linkDrawerVisible}
        setLinkDrawerVisible={setLinkDrawerVisible}
        linkFormRef={linkFormRef}
        resourceTypeList={resourceTypeList}
        form={form}
        formData={formData}
        setFormData={setFormData}
      />
    </PageContainer>
  );
};

export default EditPage;

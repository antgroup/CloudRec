import { JSONEditor, RegoEditor } from '@/components/Editor';
import { PLATFORM_THEME_WARN } from '@/constants';
import WhiteListInstance from '@/pages/RuleManagement/WhiteList/components/WhiteListInstance';
import {
  querySaveOrUpdateWhiteRule,
  queryWhitedContentByRiskId,
  queryWhiteListRuleById,
  queryWhiteListRuleExampleData,
  queryWhiteListTestRun,
  queryWhiteRuleGrabLock,
} from '@/services/rule/RuleController';
import { valueListAsValueEnum } from '@/utils/shared';
import {
  ActionType,
  EditableFormInstance,
  EditableProTable,
  ProCard,
  ProColumns,
  ProForm,
  ProFormDependency,
  ProFormInstance,
  ProFormSegmented,
  ProFormSelect,
  ProFormText,
  ProFormTextArea,
} from '@ant-design/pro-components';
import { useIntl, useModel, useRequest } from '@umijs/max';
import {
  Button,
  Col,
  Drawer,
  Flex,
  Form,
  message,
  Row,
  Spin,
  Typography,
} from 'antd';
import { MessageType } from 'antd/es/message/interface';
import { debounce } from 'lodash';
import { SegmentedValue } from 'rc-segmented';
import React, {
  Dispatch,
  SetStateAction,
  useEffect,
  useRef,
  useState,
} from 'react';
import {
  deserializeData,
  deserializeUniqueData,
  serializeData,
  WHITELIST_DEFAULT_CODE_EDITOR,
  WhiteListRuleTypeList,
} from '../const';
import styles from '../index.less';
const { Title } = Typography;

const EDITOR_HEIGHT = '506px';
// Throttling time
const DEBOUNCE_TIME = 600;

interface IWhiteListDrawerProps {
  editDrawerVisible: boolean;
  setEditDrawerVisible: Dispatch<SetStateAction<boolean>>;
  whiteListDrawerInfo: API.BaseWhiteListRuleInfo & { isEditMode?: boolean };
  tableActionRef?: React.RefObject<ActionType | undefined>;
}

type RuleDataSourceType = {
  idx: React.Key;
  key?: string;
  keyName?: string;
  operator?: string;
  value?: string;
  children?: RuleDataSourceType[];
};

// White List Configuration
const EditDrawerForm: React.FC<IWhiteListDrawerProps> = (props) => {
  // Global Info
  const { whiteListConfigList, allRuleList } = useModel('rule');
  // Component Props
  const {
    editDrawerVisible,
    setEditDrawerVisible,
    whiteListDrawerInfo,
    tableActionRef,
  } = props;
  const { id, riskId, isEditMode = true } = whiteListDrawerInfo;
  // 获取锁状态
  const isLockHolder = (whiteListDrawerInfo as any)?.isLockHolder || false;
  // 是否为只读模式
  const isReadOnly = !isEditMode;
  // 抢锁按钮Loading
  const [grabLockLoading, setGrabLockLoading] = useState<boolean>(false);
  // Message Instance
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // ProForm Instance
  const formRef = useRef<ProFormInstance<any>>();
  // Conditional Configuration ActionRef
  const actionRef = useRef<ActionType>();
  // Conditional configuration editable line key
  const [editableKeys, setEditableRowKeys] = useState<React.Key[]>([]);
  // Conditional configuration FormRef
  const editorFormRef = useRef<EditableFormInstance<RuleDataSourceType>>();
  // Submit button Loading
  const [submitLoading, setSubmitLoading] = useState<boolean>(false);
  // // White List Details JSON
  const [whiteListInstanceVisible, setWhiteListInstanceVisible] =
    useState<boolean>(false);
  // Code Editor(Rego)
  const [codeEditor, setCodeEditor] = useState(WHITELIST_DEFAULT_CODE_EDITOR);
  // Input
  const [inputEditor, setInputEditor] = useState(``);
  // Output
  const whiteListInstanceInfo = useRef({
    outputEditor: ``,
  });
  // Rego Encoding
  const onRegoEditorChange = (value: string): void => {
    setCodeEditor(value);
  };
  // Input Value
  const onInputEditorChange = (value: string): void => {
    setInputEditor(value);
  };

  const initDrawer = (): void => {
    setInputEditor(``);
    formRef.current?.resetFields();
  };

  const onClickCloseDrawerForm = (): void => {
    setEditDrawerVisible(false);
  };

  // 抢锁功能
  const onClickGrabLock = async (): Promise<void> => {
    setGrabLockLoading(true);
    const postBody = { id: id };
    const r = await queryWhiteRuleGrabLock(postBody);
    setGrabLockLoading(false);
    if (r.code === 200) {
      messageApi.success(
        intl.formatMessage({
          id: 'common.message.text.edit.success',
        }),
      );
      // 抢锁成功后切换到编辑模式
       if (whiteListDrawerInfo) {
         whiteListDrawerInfo.isEditMode = true;
         (whiteListDrawerInfo as any).isLockHolder = true;
       }
      // 重新加载数据
      if (id) {
        requestWhiteListRuleDetailById(id);
      }
      tableActionRef?.current?.reloadAndRest?.();
    }
  };

  // Submit subscription information
  const onClickFinishForm = async (
    formData: Record<string, any>,
  ): Promise<void> => {
    setSubmitLoading(true);
    const postBody: API.BaseWhiteListRuleInfo = {
      ...serializeData(formData),
      regoContent: codeEditor,
    };
    if (id) postBody.id = id;
    if (riskId) postBody.enable = 1;
    const r = await querySaveOrUpdateWhiteRule(postBody);
    setSubmitLoading(false);
    if (r.code === 200 && r.msg === 'success') {
      if (id) {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.edit.success' }),
        );
      } else {
        messageApi.success(
          intl.formatMessage({ id: 'common.message.text.add.success' }),
        );
      }
      setEditDrawerVisible(false);
      tableActionRef?.current?.reloadAndRest?.();
    }
  };

  // Detecting detailed data
  const { run: requestWhiteListRuleExampleData } = useRequest(
    (riskRuleCode?: string) => {
      return queryWhiteListRuleExampleData({ riskRuleCode: riskRuleCode });
    },
    {
      manual: true,
      formatResult: (result): void => {
        if (result.msg === 'success') {
          const { content } = result;
          try {
            setInputEditor(JSON.stringify({ ...content }, null, 4) || '');
          } catch (e) {
            console.info('Error', e);
          }
        }
      },
    },
  );

  // Detecting detailed data
  const {
    run: requestWhiteListRuleDetailById,
    loading: whiteListRuleDetailLoading,
  } = useRequest(
    (id) => {
      return queryWhiteListRuleById({ id: id });
    },
    {
      manual: true,
      formatResult: (r: any) => {
        const { content } = r;
        return deserializeData(content) || {};
      },
      onSuccess: (data): void => {
        const {
          condition,
          ruleType,
          ruleName,
          ruleDesc,
          ruleConfigList,
          editableKeyList,
          riskRuleCode,
          regoContent,
        } = data;
        formRef.current?.setFieldsValue({
          ruleType,
          ruleName,
          ruleDesc,
          ruleConfigList,
          condition,
          riskRuleCode,
        });
        setCodeEditor(regoContent);
        // Set existing conditions to editable state
        setEditableRowKeys(editableKeyList);
        if (ruleType === WhiteListRuleTypeList[1].value) {
          requestWhiteListRuleExampleData(riskRuleCode);
        }
      },
    },
  );

  // Detecting detailed whited content by riskId
  const {
    run: requestWhitedContentByRiskId,
    loading: whitedContentByRiskILoading,
  } = useRequest(
    (postBody: API.BaseWhiteListRuleInfo) =>
      queryWhitedContentByRiskId(postBody),
    {
      manual: true,
      formatResult: (r) => deserializeUniqueData(r?.content) || {},
      onSuccess: (data): void => {
        const {
          condition,
          ruleType,
          ruleName,
          ruleDesc,
          ruleConfigList,
          editableKeyList,
          riskRuleCode,
        } = data;
        formRef.current?.setFieldsValue({
          ruleType,
          ruleName,
          ruleDesc,
          ruleConfigList,
          condition,
          riskRuleCode,
        });
        // Set existing conditions to editable state
        setEditableRowKeys(editableKeyList);
      },
    },
  );

  useEffect((): void => {
    if (editDrawerVisible && id) {
      // Edit
      requestWhiteListRuleDetailById(id);
    } else if (editDrawerVisible && riskId) {
      // Risk add to white list
      requestWhitedContentByRiskId({ riskId });
    } else if (!editDrawerVisible) {
      initDrawer();
    }
  }, [editDrawerVisible]);

  const handleWhiteListRuleChange = (value: SegmentedValue) => {
    if (value === WhiteListRuleTypeList[1].value) {
      requestWhiteListRuleExampleData(
        formRef.current?.getFieldValue('riskRuleCode'),
      );
    }
  };

  // Execute immediately
  const onClickExecuteWhiteListRule = async () => {
    const postBody: API.BaseWhiteListRuleInfo = {
      ...serializeData(formRef.current?.getFieldsValue() || {}),
      regoContent: codeEditor,
    };
    // Type: REGO
    if (
      formRef.current?.getFieldValue('ruleType') ===
      WhiteListRuleTypeList[1].value
    ) {
      postBody.input = inputEditor;
    }
    const hide: MessageType = messageApi.loading(
      intl.formatMessage({ id: 'common.message.text.execute.loading' }),
    );
    const r = await queryWhiteListTestRun(postBody);
    hide();
    if (r.code === 200) {
      whiteListInstanceInfo.current.outputEditor = r.content;
      setWhiteListInstanceVisible(true);
      messageApi.success(
        intl.formatMessage({
          id: 'common.message.text.execute.success',
        }),
      );
    }
  };

  const ruleConfigColumns: ProColumns<RuleDataSourceType>[] = [
    {
      title: intl.formatMessage({
        id: 'involve.extend.title.serial.number',
      }),
      dataIndex: 'id',
      editable: false,
      width: 100,
      align: 'center',
      render: (_, record, index: number) => {
        return index + 1;
      },
    },
    {
      title: intl.formatMessage({
        id: 'rule.module.text.variable.name',
      }),
      dataIndex: 'key',
      formItemProps: {
        rules: [
          {
            required: true,
          },
        ],
      },
      valueType: 'select',
      fieldProps: (_, { rowIndex }) => {
        const array =
          whiteListConfigList?.map((item) => ({
            label: item.keyName,
            value: item.key,
          })) || [];
        return {
          options: array,
          allowClear: false,
          onSelect: (): void => {
            // Reset [Relationship Selection, Variable Values] parameters every time selected
            editorFormRef.current?.setRowData?.(rowIndex, {
              operator: undefined,
              value: undefined,
            });
          },
        };
      },
    },
    {
      title: intl.formatMessage({
        id: 'involve.extend.title.condition',
      }),
      dataIndex: 'operator',
      formItemProps: {
        rules: [
          {
            required: true,
          },
        ],
      },
      valueType: 'select',
      fieldProps: (form, { rowIndex }) => {
        if (isReadOnly) return { options: [] };
        const key = editorFormRef.current?.getRowData?.(rowIndex)?.key;
        if (!key) return [];
        const array = whiteListConfigList?.find((item) => item.key === key);
        const optionList = array?.operatorList?.map((item: string) => ({
          label: item,
          value: item,
        }));
        return { options: optionList || [] };
      },
    },
    {
      title: intl.formatMessage({
        id: 'rule.module.text.variable.value',
      }),
      dataIndex: 'value',
      formItemProps: {
        rules: [
          {
            required: true,
          },
        ],
      },
      valueType: (record) => {
        // @ts-ignore
        if (['resourceId', 'ip', 'resourceName']?.includes(record?.key))
          return 'text';
        return 'select';
      },
      fieldProps: (form, { rowIndex }) => {
        if (isReadOnly) return { options: [] };
        const key = editorFormRef.current?.getRowData?.(rowIndex)?.key;
        // @ts-ignore
        if (['resourceId', 'ip', 'resourceName']?.includes(key)) return {};
        if (!key) return [];
        const array = whiteListConfigList?.find((item) => item.key === key);
        const optionList = array?.value?.map((item: Record<string, any>) => ({
          label: item?.valueName,
          value: item?.value,
        }));
        return {
          showSearch: true,
          options: optionList || [],
        };
      },
    },
    {
      title: intl.formatMessage({
        id: 'cloudAccount.extend.title.cloud.operate',
      }),
      valueType: 'option',
      width: 140,
      render: () => [],
    },
  ];

  const RULE_ENGINE_MODULE = () => (
    <ProCard
      style={{ marginBottom: 20 }}
      bodyStyle={{
        backgroundColor: 'rgb(245, 245, 245)',
        padding: '0 20px 16px 20px',
      }}
    >
      <EditableProTable<RuleDataSourceType>
        rowKey="idx"
        name="ruleConfigList"
        actionRef={actionRef}
        editableFormRef={editorFormRef}
        headerTitle={
          <div style={{ fontSize: 14 }}>
            {intl.formatMessage({
              id: 'involve.extend.title.conditional.config',
            })}
          </div>
        }
        recordCreatorProps={isReadOnly ? undefined : {
          creatorButtonText: intl.formatMessage({
            id: 'involve.extend.title.addRowConfig',
          }),
          record: () => ({
            idx: (Math.random() * 1000000).toFixed(0),
          }),
        }}
        onChange={() => formRef.current?.setFieldValue('condition', undefined)}
        columns={ruleConfigColumns}
        editable={isReadOnly ? undefined : {
          type: 'multiple',
          editableKeys,
          onChange: setEditableRowKeys,
          actionRender: (row, config, defaultDom) => {
            return [defaultDom.delete];
          },
        }}
      />

      <ProFormDependency name={['ruleConfigList']}>
        {({ ruleConfigList }) => {
          return (
            <Row>
              <Col span={14}>
                <ProFormText
                  label={intl.formatMessage({
                    id: 'involve.extend.title.logical',
                  })}
                  name={'condition'}
                  fieldProps={{
                    placeholder: intl.formatMessage({
                      id: 'involve.extend.title.logical.example',
                    }),
                  }}
                  rules={[
                    {
                      required: ruleConfigList?.length > 1,
                    },
                  ]}
                  disabled={isReadOnly}
                />
              </Col>
              <Col>
                <Button
                  type={'link'}
                  style={{ paddingRight: 0, marginBottom: 24 }}
                  onClick={onClickExecuteWhiteListRule}
                >
                  {intl.formatMessage({
                    id: 'common.button.text.test',
                  })}
                </Button>
              </Col>
            </Row>
          );
        }}
      </ProFormDependency>
    </ProCard>
  );

  const REGO_MODULE = () => (
    <div className={styles['regoWrap']}>
      <Row className={styles['regoMain']} gutter={16}>
        <Col md={14} span={24}>
          <Title
            level={5}
            className={styles['customTitle']}
            style={{ marginBottom: 16 }}
          >
            The Rego PlayGround
          </Title>
          <RegoEditor
            editorKey={'WHITE_LIST_REGO_EDITOR'}
            value={codeEditor}
            onChange={onRegoEditorChange}
            editorStyle={{ height: EDITOR_HEIGHT }}
            readOnly={isReadOnly}
          />
        </Col>

        <Col md={10} span={24}>
          <Title level={5} className={styles['customTitle']}>
            <Flex justify={'space-between'} align={'center'}>
              <span>INPUT</span>
              <Button
                  type={'link'}
                  style={{ paddingRight: 0 }}
                  onClick={onClickExecuteWhiteListRule}
                  disabled={isReadOnly}
                >
                  {intl.formatMessage({
                    id: 'common.button.text.test',
                  })}
                </Button>
            </Flex>
          </Title>

          <JSONEditor
            editorStyle={{ height: EDITOR_HEIGHT }}
            editorKey={'WHITE_LIST_INPUT_EDITOR'}
            value={inputEditor}
            onChange={onInputEditorChange}
            readOnly={isReadOnly}
          />
        </Col>
      </Row>
    </div>
  );

  return (
    <>
      <Drawer
        title={
          id
            ? isReadOnly
              ? intl.formatMessage({
                  id: 'common.button.text.view',
                }) + intl.formatMessage({
                  id: 'rule.extend.text.whiteList.title',
                })
              : intl.formatMessage({
                  id: 'rule.extend.title.edit.whiteList',
                })
            : intl.formatMessage({
                id: 'rule.module.text.createWhiteList',
              })
        }
        width={'64%'}
        destroyOnClose
        open={editDrawerVisible}
        onClose={onClickCloseDrawerForm}
        styles={{
          body: {
            paddingBottom: 52,
          },
        }}
      >
        {contextHolder}
        <Spin
          spinning={whiteListRuleDetailLoading || whitedContentByRiskILoading}
        >
          {/* 锁状态提示 */}
          {id && !isLockHolder && (
            <div style={{ 
              marginBottom: 16, 
              padding: '12px 16px', 
              backgroundColor: '#fff7e6', 
              border: '1px solid #ffd591', 
              borderRadius: '6px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <span style={{ color: '#d46b08' }}>
                {intl.formatMessage({ id: 'rule.message.not.holding.lock' })}
              </span>
              <Button
                type="primary"
                size="small"
                loading={grabLockLoading}
                onClick={onClickGrabLock}
              >
                {intl.formatMessage({ id: 'rule.table.columns.text.grab.lock' })}
              </Button>
            </div>
          )}
          <ProForm<{
            ruleConfigList: RuleDataSourceType[];
          }>
            onFinish={onClickFinishForm}
            formRef={formRef}
            layout={'horizontal'}
            submitter={{
              submitButtonProps: {
                loading: submitLoading,
                disabled: isReadOnly,
              },
              render: (props, dom) => (
                <Flex justify={'end'} gap="small">
                  {isReadOnly ? (
                    <>
                      <Button onClick={() => onClickCloseDrawerForm()}>
                        {intl.formatMessage({
                          id: 'common.button.text.close',
                        })}
                      </Button>
                    </>
                  ) : (
                    <>
                      <Button onClick={() => onClickCloseDrawerForm()}>
                        {intl.formatMessage({
                          id: 'common.button.text.cancel',
                        })}
                      </Button>
                      {dom}
                    </>
                  )}
                </Flex>
              ),
            }}
          >
            <ProFormSegmented
              name="ruleType"
              label={intl.formatMessage({
                id: 'rule.extend.text.whiteList.type',
              })}
              initialValue={WhiteListRuleTypeList[0].value}
              valueEnum={valueListAsValueEnum(WhiteListRuleTypeList)}
              formItemProps={{
                rules: [
                  {
                    required: true,
                    message: intl.formatMessage({
                      id: 'rule.extend.text.select.whiteList.type',
                    }),
                  },
                ],
              }}
              fieldProps={{ onChange: handleWhiteListRuleChange }}
              disabled={isReadOnly}
            />

            <ProFormText
              label={intl.formatMessage({
                id: 'rule.extend.text.whiteList.title',
              })}
              name={'ruleName'}
              formItemProps={{
                rules: [
                  {
                    required: true,
                  },
                ],
              }}
              disabled={isReadOnly}
            />

            <ProFormTextArea
              label={intl.formatMessage({
                id: 'rule.extend.text.whiteList.describe',
              })}
              name={'ruleDesc'}
              formItemProps={{
                rules: [
                  {
                    required: false,
                  },
                ],
              }}
              disabled={isReadOnly}
            />

            <ProFormDependency name={['ruleType']}>
              {({ ruleType }) => {
                return (
                  <ProFormSelect
              label={intl.formatMessage({
                id: 'rule.extend.text.risk.rule.code',
              })}
              disabled={!!riskId || isReadOnly}
              name={'riskRuleCode'}
              formItemProps={{
                rules: [
                  {
                    required: false,
                  },
                ],
              }}
              options={allRuleList || []}
              fieldProps={{
                showSearch: true,
                filterOption: true,
                onChange: debounce((value): void => {
                  if (ruleType === WhiteListRuleTypeList[1].value)
                    requestWhiteListRuleExampleData(value);
                }, DEBOUNCE_TIME),
              }}
            />
                );
              }}
            </ProFormDependency>

            <ProFormDependency name={['ruleType']}>
              {({ ruleType }) => {
                if (ruleType === WhiteListRuleTypeList[1].value) {
                  return REGO_MODULE();
                } else {
                  return RULE_ENGINE_MODULE();
                }
              }}
            </ProFormDependency>

            {riskId && (
              <Form.Item>
                <div style={{ color: PLATFORM_THEME_WARN, fontSize: '13px' }}>
                  * 白名单提交后将执行风险扫描（预计30分钟生效），请勿重复提交
                </div>
              </Form.Item>
            )}
          </ProForm>
        </Spin>
      </Drawer>

      <WhiteListInstance
        whiteListInstanceVisible={whiteListInstanceVisible}
        setWhiteListInstanceVisible={setWhiteListInstanceVisible}
        whiteListInstanceInfo={whiteListInstanceInfo.current}
      />
    </>
  );
};

export default EditDrawerForm;

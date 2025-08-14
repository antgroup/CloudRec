import { InfoCircleOutlined, EditOutlined } from '@ant-design/icons';
import { ProFormText } from '@ant-design/pro-components';
import { Button, Form } from 'antd';
import JSONEditor from '@/components/Editor/JSONEditor';
import { useIntl } from 'umi';
import { CloudCredentialEditorProps, CloudAccountCredentials } from './types';

const CloudCredentialEditor: React.FC<CloudCredentialEditorProps> = ({
  type,
  fields,
  accountId,
  visible,
  onVisibleChange,
  value,
  onChange
}) => {
  const intl = useIntl();
  const handleFieldChange = (fieldName: keyof CloudAccountCredentials, fieldValue: string) => {
    const newCredentials: CloudAccountCredentials = { ...(value || {}) };
    newCredentials[fieldName] = fieldValue;
    onChange?.(newCredentials);
  };
  const handleJsonChange = (jsonValue: string) => {
    const validJsonValue = jsonValue?.trim() || '{}';
    onChange?.({ credentialsJson: validJsonValue } as CloudAccountCredentials);
  };

  if (accountId && !visible) {
    return (
      <Form.Item label={intl.formatMessage({ id: 'cloudAccount.form.credential' })} name="action">
        <Button
          type="link"
          onClick={() => onVisibleChange(true)}
          style={{ padding: '4px 0', color: '#2f54eb' }}
        >
          <EditOutlined />
        </Button>
      </Form.Item>
    );
  }

  if (!visible) return null;

  if (type === 'json') {
    return (
      <ProFormText
        name="credentialsJson"
        label="GCP KEY"
        initialValue={value?.credentialsJson || '{}'}
        rules={[{
          required: true,
          validator: async (_: any, value: string) => {
            if (!value?.trim()) {
              throw new Error('Please enter a valid GCP KEY');
            }
            try {
              JSON.parse(value);
            } catch (e) {
              throw new Error('Please enter a valid GCP KEY in JSON format');
            }
          },
        }]}
      >
        <JSONEditor
          value={value?.credentialsJson || '{}'}
          onChange={handleJsonChange}
          editorStyle={{ height: '240px' }}
          editorKey="CREDENTIALS_JSON_EDITOR"
        />
      </ProFormText>
    );
  }

  return (
    <>
      {fields.map(field => {
        const fieldName = field.name as keyof CloudAccountCredentials;
        return (
          <ProFormText
            key={fieldName}
            name={['credentials', fieldName]}
            label={field.label}
            rules={[{ required: field.required }]}
            fieldProps={{
              type: field.type || 'text',
              onChange: (e) => handleFieldChange(fieldName, e.target.value)
            }}
          />
        );
      })}
    </>
  );
};

export default CloudCredentialEditor;
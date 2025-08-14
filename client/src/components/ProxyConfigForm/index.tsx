import React from 'react';
import { ProFormTextArea } from '@ant-design/pro-components';
import { ProxyConfig } from '@/components/CloudCredentialEditor/types';
import { useIntl } from 'umi';

interface ProxyConfigFormProps {
  value?: ProxyConfig;
  onChange?: (config: ProxyConfig) => void;
}

const ProxyConfigForm: React.FC<ProxyConfigFormProps> = () => {
  const intl = useIntl();
  return (
    <ProFormTextArea
      name="proxyConfig"
      label={intl.formatMessage({ id: 'cloudAccount.form.proxy' })}
      placeholder={intl.formatMessage({ id: 'cloudAccount.form.proxy.placeholder' })}
    />
  );
};

export default ProxyConfigForm;
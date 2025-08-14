export interface FieldConfig {
  name: string;
  label: string;
  required?: boolean;
  type?: 'text' | 'password';
}

export interface CloudCredentialEditorProps {
  type: 'json' | 'basic' | 'exclusive' | 'extend';
  fields: FieldConfig[];
  accountId?: number;
  visible: boolean;
  onVisibleChange: (visible: boolean) => void;
  value?: CloudAccountCredentials;
  onChange?: (value: CloudAccountCredentials) => void;
}

export interface ProxyConfig {
  proxyConfig?: string;
}

export interface CloudAccountCredentials {
  ak?: string;
  sk?: string;
  endpoint?: string;
  regionId?: string;
  projectId?: string;
  iamEndpoint?: string;
  ecsEndpoint?: string;
  elbEndpoint?: string;
  evsEndpoint?: string;
  vpcEndpoint?: string;
  obsEndpoint?: string;
  credentialsJson?: string;
}

export interface CloudAccountFormData {
  cloudAccountId: string;
  email?: string;
  alias: string;
  tenantId: string;
  platform: string;
  resourceTypeList: string[];
  credentials: CloudAccountCredentials;
  proxyConfig?: string;
  site?: string;
  owner?: string;
  // Support for inverse selection of cloud services
  enableInverseSelection?: boolean;
}
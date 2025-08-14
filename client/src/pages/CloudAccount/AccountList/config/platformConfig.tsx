import { Rule } from 'antd/es/form';

export interface PlatformConfig {
  type: 'json' | 'basic' | 'exclusive' | 'extend';
  fields: Array<{
    name: string;
    label: string;
    required?: boolean;
  }>;
  hasProxy?: boolean;
}

export const PLATFORM_CONFIGS: Record<string, PlatformConfig> = {
  'ALI_CLOUD': {
    type: 'basic',
    fields: [
      { name: 'ak', label: 'AK', required: true },
      { name: 'sk', label: 'SK', required: true }
    ],
    hasProxy: true
  },
  'HUAWEI_CLOUD': {
    type: 'basic',
    fields: [
      { name: 'ak', label: 'AK', required: true },
      { name: 'sk', label: 'SK', required: true }
    ]
  },
  'BAIDU_CLOUD': {
    type: 'basic',
    fields: [
      { name: 'ak', label: 'AK', required: true },
      { name: 'sk', label: 'SK', required: true }
    ]
  },
  'AWS': {
    type: 'basic',
    fields: [
      { name: 'ak', label: 'AK', required: true },
      { name: 'sk', label: 'SK', required: true }
    ]
  },
  'TENCENT_CLOUD': {
    type: 'basic',
    fields: [
      { name: 'ak', label: 'AK', required: true },
      { name: 'sk', label: 'SK', required: true }
    ]
  },
  'KINGSOFT_CLOUD': {
    type: 'basic',
    fields: [
      { name: 'ak', label: 'AK', required: true },
      { name: 'sk', label: 'SK', required: true }
    ]
  },
  'AZURE': {
    type: 'basic',
    fields: [
      { name: 'ak', label: 'AK', required: true },
      { name: 'sk', label: 'SK', required: true }
    ]
  },
  'GCP': {
    type: 'json',
    fields: [
      { name: 'credentialsJson', label: 'GCP KEY', required: true }
    ]
  },
  'ALI_CLOUD_PRIVATE': {
    type: 'exclusive',
    fields: [
      { name: 'ak', label: 'AK', required: true },
      { name: 'sk', label: 'SK', required: true },
      { name: 'endpoint', label: 'Endpoint', required: true },
      { name: 'regionId', label: 'RegionId', required: true }
    ]
  },
  'HUAWEI_CLOUD_PRIVATE': {
    type: 'extend',
    fields: [
      { name: 'ak', label: 'AK', required: true },
      { name: 'sk', label: 'SK', required: true },
      { name: 'iamEndpoint', label: 'Iam_Endpoint', required: true },
      { name: 'ecsEndpoint', label: 'Ecs_Endpoint', required: true },
      { name: 'elbEndpoint', label: 'Elb_Endpoint', required: true },
      { name: 'evsEndpoint', label: 'Evs_Endpoint', required: true },
      { name: 'vpcEndpoint', label: 'Vpc_Endpoint', required: true },
      { name: 'obsEndpoint', label: 'Obs_Endpoint', required: true },
      { name: 'regionId', label: 'RegionId', required: true },
      { name: 'projectId', label: 'ProjectId' }
    ]
  }
  // [5.3] ADD_NEW_CLOUD: Display according to the authentication method

};

export const FORM_VALIDATION_RULES = {
  cloudAccountId: [{ required: true, message: 'Please enter your cloud account ID' }],
  alias: [{ required: true, message: 'Please enter the alias of your cloud account' }],
  tenantId: [{ required: true, message: 'Please select the tenant' }],
  platform: [{ required: true, message: 'Please select the cloud platform' }]
} as Record<string, Rule[]>;



export const JSON_EDITOR_LIST = ['GCP'];
export const BASIC_EDITOR_LIST = ['ALI_CLOUD', 'HUAWEI_CLOUD', 'BAIDU_CLOUD', 'AWS', 'TENCENT_CLOUD', 'KINGSOFT_CLOUD','AZURE'];
export const EXCLUSIVE_EDITOR_LIST = ['ALI_CLOUD_PRIVATE'];
export const EXTEND_EDITOR_LIST = ['HUAWEI_CLOUD_PRIVATE'];
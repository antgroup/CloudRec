import ALI_ACCOUNT from '@/assets/images/ALI_ACCOUNT.png';
import ALI_ACCOUNT_PRIVATE from '@/assets/images/ALI_ACCOUNT_PRIVATE.png';
import ALI_CLOUD from '@/assets/images/ALI_CLOUD.png';
import ALI_CLOUD_PRIVATE from '@/assets/images/ALI_CLOUD_PRIVATE.png';
import AWS_ACCOUNT from '@/assets/images/AWS_ACCOUNT.png';
import AWS from '@/assets/images/AWS_CLOUD.png';
import AZURE from '@/assets/images/AZURE.svg';
import AZURE_ACCOUNT from '@/assets/images/AZURE_ACCOUNT.svg';
import BAIDU_ACCOUNT from '@/assets/images/BAIDU_ACCOUNT.svg';
import BAIDU_CLOUD from '@/assets/images/BAIDU_CLOUD.svg';
import CLOUD_ACCOUNT from '@/assets/images/CLOUD_ACCOUNT.png';
import CLOUD_ASSET from '@/assets/images/CLOUD_ASSET.png';
import CLOUD_COVERAGE from '@/assets/images/CLOUD_COVERAGE.svg';
import CLOUD_DEFAULT from '@/assets/images/CLOUD_DEFAULT.svg';
import CLOUD_PLATFORM from '@/assets/images/CLOUD_PLATFORM.png';
import CLOUD_RISK from '@/assets/images/CLOUD_RISK.png';
import GCP from '@/assets/images/GCP.svg';
import GCP_ACCOUNT from '@/assets/images/GCP_ACCOUNT.svg';
import HIGH_LEVEL_RISK from '@/assets/images/HIGH_LEVEL_RISK.png';
import HUAWEI_ACCOUNT from '@/assets/images/HUAWEI_ACCOUNT.png';
import HUAWEI_ACCOUNT_PRIVATE from '@/assets/images/HUAWEI_ACCOUNT_PRIVATE.png';
import HUAWEI_CLOUD from '@/assets/images/HUAWEI_CLOUD.png';
import HUAWEI_CLOUD_PRIVATE from '@/assets/images/HUAWEI_CLOUD_PRIVATE.png';
import LOW_LEVEL_RISK from '@/assets/images/LOW_LEVEL_RISK.png';
import MEDIUM_LEVEL_RISK from '@/assets/images/MEDIUM_LEVEL_RISK.png';
import TENCENT_ACCOUNT from '@/assets/images/TENCENT_ACCOUNT.png';
import TENCENT_CLOUD from '@/assets/images/TENCENT_CLOUD.png';
// [4] ADD_NEW_CLOUD : Add cloud provider icon
// import My_Cloud_Provider from '@/assets/images/My_Cloud_Provider.png';
import KINGSOFT_ACCOUNT from '@/assets/images/KINGSOFT_ACCOUNT.svg';
import KINGSOFT_CLOUD from '@/assets/images/KINGSOFT_CLOUD.svg';
import { FormattedMessage } from '@umijs/max';
import { TimeRangePickerProps } from 'antd';
import dayjs from 'dayjs';
import { ReactNode } from 'react';

export interface IValueType {
  label?: string | ReactNode;
  text?: string | ReactNode;
  value: string | number | boolean;
  color?: string;
  background?: string;
  icon?: string;
}

export const RiskLevelList: Array<IValueType> = [
  {
    text: <FormattedMessage id="home.module.risk.high" />,
    value: 'High',
    color: 'rgb(288, 43, 53)',
    background: '#FFEDEA',
    icon: HIGH_LEVEL_RISK,
  },
  {
    text: <FormattedMessage id="home.module.risk.middle" />,
    value: 'Medium',
    color: 'rgb(253, 100, 8)',
    background: '#FFE9CC',
    icon: MEDIUM_LEVEL_RISK,
  },
  {
    text: <FormattedMessage id="home.module.risk.low" />,
    value: 'Low',
    color: 'rgb(254, 192, 11)',
    background: '#DFF5EF',
    icon: LOW_LEVEL_RISK,
  },
];

export const UserTypeList: Array<IValueType> = [
  {
    label: <FormattedMessage id="common.tag.text.user" />,
    value: 'user',
  },
  {
    label: <FormattedMessage id="common.tag.text.admin" />,
    value: 'admin',
  },
];

export const TenantStatusList: Array<IValueType> = [
  {
    label: <FormattedMessage id="common.button.text.normal" />,
    value: 'valid',
  },
  {
    label: <FormattedMessage id="common.button.text.disable" />,
    value: 'invalid',
  },
];

// Platform Icon Mapping
export const platformURLMap = {
  ALI_CLOUD_URL: ALI_CLOUD, // Alibaba Cloud
  ALI_CLOUD_PRIVATE_URL: ALI_CLOUD_PRIVATE, // Alibaba private cloud
  HUAWEI_CLOUD_URL: HUAWEI_CLOUD, // Hua Wei Cloud
  HUAWEI_CLOUD_PRIVATE_URL: HUAWEI_CLOUD_PRIVATE, // Hua Wei private Cloud
  TENCENT_CLOUD_URL: TENCENT_CLOUD, // Tencent Cloud
  BAIDU_CLOUD_URL: BAIDU_CLOUD, // Baidu Cloud
  AWS_URL: AWS, // AWS
  GCP_URL: GCP, // Google Cloud
  AZURE_URL: AZURE, // AZURE
  // [5.1] ADD_NEW_CLOUD : Reference this icon address
  // My_Cloud_Provider_URL: My_Cloud_Provider
  KINGSOFT_CLOUD_URL: KINGSOFT_CLOUD,
};

export const overviewURLMap = {
  CLOUD_PLATFORM: CLOUD_PLATFORM, // Cloud platform
  CLOUD_ACCOUNT: CLOUD_ACCOUNT, // Cloud account
  CLOUD_ASSET: CLOUD_ASSET, // Cloud assets
  CLOUD_COVERAGE: CLOUD_COVERAGE, // Cloud coverage rate
  CLOUD_RISK: CLOUD_RISK, // Cloud risk
  CLOUD_DEFAULT: CLOUD_DEFAULT, // Cloud default icon
};

// Cloud Account Mapping
export const accountURLMap = {
  GCP: GCP_ACCOUNT,
  ALI_CLOUD: ALI_ACCOUNT,
  ALI_CLOUD_PRIVATE: ALI_ACCOUNT_PRIVATE,
  HUAWEI_CLOUD: HUAWEI_ACCOUNT,
  HUAWEI_CLOUD_PRIVATE: HUAWEI_ACCOUNT_PRIVATE,
  TENCENT_CLOUD: TENCENT_ACCOUNT,
  AWS: AWS_ACCOUNT,
  BAIDU_CLOUD: BAIDU_ACCOUNT,
  AZURE: AZURE_ACCOUNT,
  // [5.2] ADD_NEW_CLOUD : Reference this icon address
  // My_Cloud_Provider: My_Cloud_Provider_ACCOUNT
  KINGSOFT_CLOUD: KINGSOFT_ACCOUNT,
};

export const RangePresets: TimeRangePickerProps['presets'] = [
  {
    label: <FormattedMessage id="common.button.text.today" />,
    value: [dayjs(), dayjs().endOf('day')],
  },
  {
    label: <FormattedMessage id="common.button.text.last7.days" />,
    value: [dayjs().add(-7, 'd'), dayjs()],
  },
  {
    label: <FormattedMessage id="common.button.text.within.a.month" />,
    value: [dayjs().add(-30, 'd'), dayjs()],
  },
  {
    label: <FormattedMessage id="common.button.text.Within.three.months" />,
    value: [dayjs().add(-90, 'd'), dayjs()],
  },
  {
    label: <FormattedMessage id="common.button.text.Within.six.months" />,
    value: [dayjs().add(-180, 'd'), dayjs()],
  },
];

import { TranslationOutlined, GlobalOutlined, CaretDownOutlined } from '@ant-design/icons';
import { useIntl } from '@umijs/max';
import { Dropdown, Button, Menu } from 'antd';
import React from 'react';
import { setLocale } from 'umi';
import styles from './index.less';

export const LanguageList = [
  {
    label: '简体中文',
    shortLabel: 'CN',
    value: 'zh-CN',
  },
  {
    label: 'English',
    shortLabel: 'EN',
    value: 'en-US',
  },
];

// Switch Language
const SwitchLanguage: React.FC = () => {
  // Intl API
  const intl = useIntl();

  /**
   * Handle language change when menu item is clicked
   */
  const handleLanguageChange = (language: string): void => {
    setLocale(language, true);
  };

  /**
   * Get current language display info
   */
  const getCurrentLanguage = () => {
    return LanguageList.find(lang => lang.value === intl.locale) || LanguageList[0];
  };

  /**
   * Create menu items for language dropdown
   */
  const menuItems = LanguageList.map(lang => ({
    key: lang.value,
    label: lang.label,
    onClick: () => handleLanguageChange(lang.value),
  }));

  const menu = {
    items: menuItems,
  };

  return (
    <Dropdown menu={menu} placement="bottomRight">
      <Button
        className={styles['currentLanguage']}
        type={'link'}
        icon={<GlobalOutlined />}
      >
        {getCurrentLanguage().shortLabel}
        <CaretDownOutlined style={{ marginLeft: 4, fontSize: '12px' }} />
      </Button>
    </Dropdown>
  );
};
export default SwitchLanguage;

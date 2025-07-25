import { Button, Result } from 'antd';
import { ExclamationCircleOutlined } from '@ant-design/icons';
import { useIntl, history } from '@umijs/max';
import React from 'react';
import styles from './NoPermission.less';

/**
 * NoPermission Component
 * A reusable component to display no permission access page
 * @param props - Component props
 * @param props.title - Custom title for the no permission page
 * @param props.subTitle - Custom subtitle for the no permission page
 * @param props.showReturnButton - Whether to show the return button
 * @param props.onReturn - Custom return handler
 */
interface NoPermissionProps {
  title?: string;
  subTitle?: string;
  showReturnButton?: boolean;
  onReturn?: () => void;
}

const NoPermission: React.FC<NoPermissionProps> = ({
  title,
  subTitle,
  showReturnButton = true,
  onReturn,
}) => {
  // Intl API for internationalization
  const intl = useIntl();

  /**
   * Handle return button click
   * Uses custom handler if provided, otherwise navigates to home page
   */
  const handleReturn = () => {
    if (onReturn) {
      onReturn();
    } else {
      history?.push('/');
    }
  };

  return (
    <div className={styles.noPermissionContainer}>
      <Result
        icon={<ExclamationCircleOutlined />}
        status="403"
        title={
          title ||
          intl.formatMessage({ id: 'common.message.text.no.permission.title' })
        }
        subTitle={
          subTitle ||
          intl.formatMessage({
            id: 'common.message.text.no.permission.subtitle',
          })
        }
        extra={
          showReturnButton && (
            <Button type="primary" onClick={handleReturn}>
              {intl.formatMessage({ id: 'common.button.text.return' })}
            </Button>
          )
        }
      />
    </div>
  );
};

export default NoPermission;
import React from 'react';
import {useIntl, useAccess } from '@umijs/max';
import NoPermission from './NoPermission';
/**
 * PermissionWrapper Component
 * A wrapper component that checks access permissions and shows NoPermission page when access is denied
 * @param props - Component props
 * @param props.children - Child components to render when permission is granted
 * @param props.accessKey - The access key to check in the access object
 * @param props.fallback - Custom fallback component when permission is denied
 */
interface PermissionWrapperProps {
  children: React.ReactNode;
  accessKey?: string;
  fallback?: React.ReactNode;
}

const PermissionWrapper: React.FC<PermissionWrapperProps> = ({
  children,
  accessKey,
  fallback,
}) => {
  const access = useAccess();
  const intl = useIntl();
  // If no accessKey is provided, render children directly
  if (!accessKey) {
    return <>{children}</>;
  }

  // Check if user has the required permission
  const hasPermission = (access as any)[accessKey];

  // If user has permission, render children
  if (hasPermission) {
    return <>{children}</>;
  }

  // If user doesn't have permission, render fallback or NoPermission component
  return (
    <>
      {fallback || (
        <NoPermission
          title={intl.formatMessage({ id: 'common.message.text.no.permission.title' })}
          subTitle={intl.formatMessage({ id: 'common.message.text.no.permission.subtitle' })}
        />
      )}
    </>
  );
};

export default PermissionWrapper;
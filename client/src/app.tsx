// Runtime configuration
import MenuFooter from '@/components/Layout/MenuFooter';
import UserAction from '@/components/Layout/UserAction';
import { queryUserInfo } from '@/services/user/UserController';
import { RunTimeLayoutConfig } from '@@/plugin-layout/types';
import { RequestConfig } from '@@/plugin-request/request';
import { ProBreadcrumb } from '@ant-design/pro-layout';
import { history } from '@umijs/max';
import { message } from 'antd';
import React from 'react';
import './global.less';

const contentStyle: React.CSSProperties = {
  minHeight: 'calc(100vh - 56px)',
  background:
    'linear-gradient(126deg, rgba(217,242,255,0.50) 0%, rgba(242,240,252,0.50) 28%, rgba(187,210,255,0.60) 100%)',
};

// Global initialization data configuration, used for Layout user information and permission initialization
// For more information, please refer to the document：https://umijs.org/docs/api/runtime-config#getinitialstate
export async function getInitialState(): Promise<any> {
  const res: API.Result_T_ = await queryUserInfo({});
  if (res.code !== 200) return {};
  const { content } = res;
  return {
    ...content,
  };
}

// Request interceptor
const requestInterceptor = (request: any) => {
  request.headers['token'] = localStorage.getItem('JSESSIONID') || null;
  request.headers['language'] = localStorage.getItem('umi_locale') || null;
  return request;
};

// Response interceptor
const responseInterceptor = (response: any): any => {
  const errorMsg = '服务器开小差了，等下再试吧。';
  const { data } = response;
  const { content, code, msg } = data;
  if (data instanceof Blob || data instanceof ArrayBuffer) {
    return response;
  }
  // Not logged in and there is a login callback address
  // Skip redirect for invitation page
  if (code !== 200 && ['USER_NOT_LOGIN'].includes(content) && !window.location.pathname.includes('/invitation')) {
    // Preserve URL parameters when redirecting to login
    const currentSearch = window.location.search;
    history.push(`/login${currentSearch}`);
  }
  // Exclude logged in exceptions
  if (code !== 200 && !['USER_NOT_LOGIN'].includes(content)) {
    message.error('ErrorCode ' + code + ' ' + msg || errorMsg);
  }
  return response;
};

export const request: RequestConfig = {
  requestInterceptors: [requestInterceptor],
  responseInterceptors: [responseInterceptor],
  headers: {
    Credential: true,
  },
  timeout: 60000,
};
export const layout: RunTimeLayoutConfig = (props) => {
  const { userId, username, tenantId, tenantName } = props?.initialState || {};
  return {
    logo: '/favicon-light.ico',
    menu: {
      locale: false,
    },
    contentStyle,
    layout: 'mix', // Mixed navigation mode with avatars located on the upper right side
    headerRender: (!window?.location?.pathname?.includes('/login') && !window?.location?.pathname?.includes('/invitation')) as any, // As any Temporarily ignore TS type anomalies
    headerContentRender: () => <ProBreadcrumb />,
    footerRender: false,
    token: {
      header: {
        colorBgRightActionsItemHover: '#FFF',
      },
      sider: {
        colorMenuBackground: '#FFF',
        colorTextMenu: 'rgba(51, 51, 51, 1)',
        colorTextMenuItemHover: 'rgba(50,116,238,1)',
        colorBgMenuItemHover: 'rgba(230,243,254,1)',
        colorTextMenuSelected: 'rgba(50,116,238,1)', // Selected font color for menuItem
        colorBgMenuItemSelected: 'rgba(236,246,254,1)', // Select background color for menuItem
        colorBgRightActionsItemHover: '#FFF',
      },
      pageContainer: {
        paddingInlinePageContainerContent: 32,
        paddingBlockPageContainerContent: 32,
      },
    },
    rightContentRender: (value) => (
      <UserAction
        collapsed={value!.collapsed}
        userId={userId}
        username={username}
        key={'UserAction'}
        tenantId={tenantId}
        tenantName={tenantName}
      />
    ),
    menuFooterRender: (value) => <MenuFooter collapsed={value!.collapsed} />,
  };
};

import { useState, useCallback } from 'react';
import { message } from 'antd';
import { useIntl } from '@umijs/max';
import { isEmpty } from 'lodash';
import { queryGroupTypeList } from '@/services/resource/ResourceController';

export const useResourceTypes = () => {
  const intl = useIntl();
  const [loading, setLoading] = useState(false);
  const [resourceTypes, setResourceTypes] = useState([]);

  const fetchResourceTypes = useCallback(async (platform: string) => {
    if (!platform?.trim()) return;
    
    setLoading(true);
    try {
      const res = await queryGroupTypeList({ platformList: [platform] });
      if (isEmpty(res.content)) {
        setResourceTypes([]);
        message.error(
          intl.formatMessage({ id: 'cloudAccount.message.text.no.assets' })
        );
      } else {
        setResourceTypes(res?.content as any);
      }
    } catch (error) {
      message.error('获取资源类型列表失败');
      setResourceTypes([]);
    } finally {
      setLoading(false);
    }
  }, [intl]);

  return {
    loading,
    resourceTypes,
    fetchResourceTypes,
  };
};
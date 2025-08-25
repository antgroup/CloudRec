import { useEffect } from 'react';
import { isEmpty } from 'lodash';
import { useLocation } from '@umijs/max';
import { FormInstance } from 'antd';

interface UsePlatformDefaultSelectionOptions {
  platformList: any[];
  form: FormInstance;
  onPlatformChange?: (platformList: string[]) => void;
  requestResourceTypeList?: (platformList: string[]) => void;
  requestCloudAccountBaseInfoList?: (params: { platformList: string[] }) => void;
  platformFieldName?: string;
  resourceTypeFieldName?: string;
}

/**
 * Custom hook for handling default platform selection
 * Automatically selects the first platform when platformList is available and no URL parameter is specified
 * @param options - Configuration options for the hook
 */
export const usePlatformDefaultSelection = ({
  platformList,
  form,
  onPlatformChange,
  requestResourceTypeList,
  requestCloudAccountBaseInfoList,
  platformFieldName = 'platformList',
  resourceTypeFieldName = 'resourceTypeList'
}: UsePlatformDefaultSelectionOptions) => {
  const { search } = useLocation();
  const searchParams = new URLSearchParams(search);
  const platformQuery = searchParams.get('platform');

  useEffect(() => {
    // Only proceed if platformList is available and has items
    if (!platformList || platformList.length === 0) {
      return;
    }

    // Check if platform is already set via URL parameter
    if (!isEmpty(platformQuery)) {
      return;
    }

    // Check if platform is already selected in the form
    const currentPlatformList = form.getFieldValue(platformFieldName);
    if (!isEmpty(currentPlatformList)) {
      return;
    }

    // Set default platform selection to the first platform
    const firstPlatform = platformList[0]?.value || platformList[0];
    if (firstPlatform) {
      const defaultPlatformList = [firstPlatform];
      
      // Set the platform field value
      form.setFieldValue(platformFieldName, defaultPlatformList);
      
      // Clear resource type selection when platform changes
      if (resourceTypeFieldName) {
        form.setFieldValue(resourceTypeFieldName, null);
      }
      
      // Call the platform change callback if provided
      if (onPlatformChange) {
        onPlatformChange(defaultPlatformList);
      }
      
      // Request resource type list for the selected platform
      if (requestResourceTypeList) {
        requestResourceTypeList(defaultPlatformList);
      }
      
      // Request cloud account list for the selected platform
      if (requestCloudAccountBaseInfoList) {
        requestCloudAccountBaseInfoList({
          platformList: defaultPlatformList
        });
      }
    }
  }, [platformList, platformQuery, form, onPlatformChange, requestResourceTypeList, requestCloudAccountBaseInfoList, platformFieldName, resourceTypeFieldName]);
};
import { BASE_URL } from '@/services';
import { request } from '@umijs/max';

/** Execute query on cloud account list POST /api/cloudAccount/cloudAccountList */
export async function queryCloudAccountList(
  body?: API.CloudAccountResult,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/cloudAccount/cloudAccountList`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      data: body,
      ...(options || {}),
    },
  );
}

export async function queryCloudAccountBaseInfoList(
  body?: API.CloudAccountResult,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/cloudAccount/cloudAccountBaseInfoList`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      data: body,
      ...(options || {}),
    },
  );
}

/** Cloud account entry and editing POST /api/cloudAccount/saveCloudAccount */
export async function saveCloudAccount(
  body?: API.CloudAccountResult,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/cloudAccount/saveCloudAccount`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      data: body,
      ...(options || {}),
    },
  );
}

/** Rule group deletion interface DELETE /api/ruleGroup/delRuleGroup */
export async function removeCloudAccount(
  params: {
    /** id */
    id: number;
  },
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(
    `${BASE_URL}/api/cloudAccount/removeCloudAccount`,
    {
      method: 'DELETE',
      params: { ...params },
      ...(options || {}),
    },
  );
}

export async function updateCloudAccountStatus(
  body?: { accountStatus: string; cloudAccountId: string },
  options?: { [p: string]: any },
) {
  return request<API.Result_String_>(
    `${BASE_URL}/api/cloudAccount/updateCloudAccountStatus`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      data: body,
      ...(options || {}),
    },
  );
}

/** Query cloud account details GET /api/cloudAccount/cloudAccountDetail */
export async function cloudAccountDetailById(
  params?: API.CloudAccountResult,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/cloudAccount/cloudAccountDetail`,
    {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
      params: {
        ...params,
      },
      ...(options || {}),
    },
  );
}

export async function cloudAccountBaseInfoList(
  body?: { cloudAccountSearch?: string; platformList?: string[] },
  options?: { [p: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/cloudAccount/cloudAccountBaseInfoList`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      data: body,
      ...(options || {}),
    },
  );
}

export async function cloudAccountBaseInfoListV2(
  body?: { cloudAccountSearch?: string; platformList?: string[] },
  options?: { [p: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/cloudAccount/cloudAccountBaseInfoListV2`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      data: body,
      ...(options || {}),
    },
  );
}


export async function createCollectTask(
  body?: { cloudAccountId?: string },
  options?: { [p: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/cloudAccount/createCollectTask`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      data: body,
      ...(options || {}),
    },
  );
}

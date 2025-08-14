import { BASE_URL } from '@/services';
import { request } from '@umijs/max';

/** Query risk list interface: POST /api/risk/queryRiskList */
export async function queryRiskList(
  body?: API.RiskInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_RiskInfo>(`${BASE_URL}/api/risk/queryRiskList`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Query Risk Details Interface: POST /api/risk/queryRiskDetail */
export async function queryRiskDetailById(
  body?: API.RiskInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_RiskInfo>(`${BASE_URL}/api/risk/queryRiskDetail`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Ignore risk interface: POST /api/risk/ignoreRisk */
export async function ignoreRisk(
  body?: API.RiskInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/risk/ignoreRisk`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Cancel ignoring risk interface: POST /api/risk/cancelIgnoreRisk */
export async function cancelIgnoreRisk(
  body?: API.RiskInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/risk/cancelIgnoreRisk`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Cancel ignoring risk interface: POST /api/risk/operationLog */
export async function queryOperationLog(
  body?: API.RiskInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_RiskLogInfo>(`${BASE_URL}/api/risk/operationLog`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Comment on risk information: POST /api/risk/commentInformation */
export async function requestCommentInformation(
  body?: API.RiskInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(
    `${BASE_URL}/api/risk/commentInformation`,
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

/** List rule statistics interface: POST /api/risk/listRuleStatistics */
export async function listRuleStatistics(
  body?: API.RiskInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/risk/listRuleStatistics`,
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

/** List cloud account statistics interface: POST /api/risk/listCloudAccountStatistics */
export async function listCloudAccountStatistics(
  body?: API.RiskInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/risk/listCloudAccountStatistics`,
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

/** Export risk list interface: POST /api/risk/exportRiskList */
export async function exportRiskList(
  body?: API.RiskInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_RiskInfo>(`${BASE_URL}/api/risk/exportRiskList`, {
    method: 'POST',
    timeout: 1000 * 60 * 3, // Set timeout time separately
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

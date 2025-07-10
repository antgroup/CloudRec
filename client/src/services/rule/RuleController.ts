import { BASE_URL } from '@/services';
import { request } from '@umijs/max';

/** Rule group query interface: POST /api/ruleGroup/queryRuleGroupList */
export async function queryRuleGroupList(
  body?: API.RuleGroupInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_RuleGroupInfo_>(
    `${BASE_URL}/api/ruleGroup/queryRuleGroupList`,
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

/** New Rule Group | Edit Interface: POST /api/ruleGroup/saveRuleGroup */
export async function saveRuleGroup(
  body?: API.RuleGroupInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(
    `${BASE_URL}/api/ruleGroup/saveRuleGroup`,
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

/** Rule group deletion interface: DELETE /api/ruleGroup/delRuleGroup */
export async function delRuleGroup(
  params: {
    /** id */
    id: number;
  },
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/ruleGroup/delRuleGroup`, {
    method: 'DELETE',
    params: { ...params },
    ...(options || {}),
  });
}

/** Rule group detection interface: DELETE /api/ruleGroup/scanByGroup */
export async function scanByGroup(
  params: {
    /** id */
    id: number;
  },
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/ruleGroup/scanByGroup`, {
    method: 'POST',
    params: { ...params },
    ...(options || {}),
  });
}

/** Rule query interface: POST /api/rule/queryRuleList */
export async function queryRuleList(
  body?: API.RuleProjectInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result>(`${BASE_URL}/api/rule/queryRuleList`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Rule deletion interface: DELETE /api/ruleGroup/delRuleGroup */
export async function deleteRule(
  params: {
    /** id */
    id: number;
  },
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/rule/deleteRule`, {
    method: 'DELETE',
    params: { ...params },
    ...(options || {}),
  });
}

/** Rule Creation | Editing Interface: POST /api/rule/saveRule */
export async function saveRule(
  body?: API.RuleProjectInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/rule/saveRule`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Rule detection interface: POST /api/rule/scanByRule */
export async function scanByRule(
  body?: API.RuleProjectInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/rule/scanByRule`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Modify rule status interface: POST /api/rule/changeRuleStatus */
export async function changeRuleStatus(
  body?: API.RuleProjectInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/rule/changeRuleStatus`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Copy Rule Interface: POST /api/rule/copyRule */
export async function copyRule(
  body?: API.RuleProjectInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/rule/copyRule`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Rule details query interface: POST /api/rule/queryRuleDetail */
export async function queryRuleDetail(
  body?: API.RuleGroupInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/rule/queryRuleDetail`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Cloud platform + asset type query example data interface: POST /api/resource/queryResourceExampleData */
export async function queryResourceExampleData(
  body?: API.RuleGroupInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/resource/queryResourceExampleData`,
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

/** List of query rule types: POST /rule/queryRuleTypeList */
export async function queryRuleTypeList(
  body?: API.RuleGroupInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result>(`${BASE_URL}/api/rule/queryRuleTypeList`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

/** Rule group full query interface: GET /api/rule/queryRuleGroupNameList */
export async function queryRuleGroupNameList(
  params?: { [key: string]: any },
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/ruleGroup/queryRuleGroupNameList`,
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

/** Query and parse progress interface: GET /api/progress/getProgress */
export async function queryAnalysisProgress(
  params?: { taskId: number },
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/progress/getProgress`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    params: {
      ...params,
    },
    ...(options || {}),
  });
}

/** Rule execution, supports task cancellation: POST /api/progress/cancelTask */
export async function queryCancelTask(
  body?: {
    taskId: number | string;
  },
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/progress/cancelTask`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** When editing a rule group, you can select the rules within the group interface: GET /api/rule/queryAllRuleList */
export async function queryAllRuleList(
  params?: { [key: string]: any },
  options?: { [key: string]: any },
) {
  return request<API.Result>(`${BASE_URL}/api/rule/queryAllRuleList`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    params: {
      ...params,
    },
    ...(options || {}),
  });
}

/** Query rule group details interface: GET /api/ruleGroup/queryRuleGroupDetail */
export async function queryRuleGroupDetail(
  params?: { id: number },
  options?: { [key: string]: any },
) {
  return request<API.Result>(`${BASE_URL}/api/ruleGroup/queryRuleGroupDetail`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    params: {
      ...params,
    },
    ...(options || {}),
  });
}

/** Add / Update whitelist rules: POST /api/whitedRule/save */
export async function querySaveOrUpdateWhiteRule(
  body?: API.BaseWhiteListRuleInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/whitedRule/save`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Example of Input in Rego Mode: POST /api/whitedRule/queryExampleData */
export async function queryWhiteListRuleExampleData(
  body?: API.BaseWhiteListRuleInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/whitedRule/queryExampleData`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Rule trial run: POST /api/whitedRule/testRun */
export async function queryWhiteListTestRun(
  body?: API.BaseWhiteListRuleInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/whitedRule/testRun`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** White List Rule List: POST /api/whitedRule/list */
export async function queryWhiteRuleList(
  body?: API.BaseWhiteListRuleInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/whitedRule/list`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Lock before editing: POST /api/whitedRule/grabLock/{id} */
export async function queryWhiteRuleGrabLock(
  body?: API.BaseWhiteListRuleInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/whitedRule/grabLock/${body!.id}`,
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

/** View details By id: POST /api/whitedRule/{id} */
export async function queryWhiteListRuleById(
  params?: { [key: string]: any },
  options?: { [key: string]: any },
) {
  return request<API.Result>(`${BASE_URL}/api/whitedRule/${params!.id}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    params: {
      ...params,
    },
    ...(options || {}),
  });
}

/** Delete White List Rule By id: POST /api/whitedRule/delete/{id} */
export async function queryDeleteWhiteListRuleById(
  body?: API.BaseWhiteListRuleInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/whitedRule/delete/${body!.id}`,
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

export async function queryWhitedConfigList(
  params?: { [key: string]: any },
  options?: { [key: string]: any },
) {
  return request<API.Result>(`${BASE_URL}/api/whitedRule/getWhitedConfigList`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    params: {
      ...params,
    },
    ...(options || {}),
  });
}

/** Enable/disable whitelist rule: POST /api/whitedRule/changeStatus */
export async function queryChangeWhiteListRuleStatus(
  body?: API.BaseWhiteListRuleInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/whitedRule/changeStatus`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

/** Export rule list interface: POST /api/rule/download */
export async function queryExportRuleList(
  params?: API.BaseWhiteListRuleInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result>(`${BASE_URL}/api/rule/download`, {
    method: 'POST',
    timeout: 1000 * 60 * 3, // Set timeout time separately
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...params,
    },
    ...(options || {}),
  });
}

/** query Whited Content By Risk ID: POST  /api/whitedRule/queryWhitedContentByRisk/{riskId} */
export async function queryWhitedContentByRiskId(
  body?: API.BaseWhiteListRuleInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/whitedRule/queryWhitedContentByRisk/${body?.riskId} `,
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

/** 从Github同步规则: POST /api/rule/loadRuleFromGithub */
export async function loadRuleFromGithub(
  body?: { coverage?: boolean },
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/rule/loadRuleFromGithub`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

// checkExistNewRule
export async function checkExistNewRule() {
  return request<API.Result_Number_>(`${BASE_URL}/api/rule/checkExistNewRule`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  });
}

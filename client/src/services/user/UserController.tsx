import { BASE_URL } from '@/services';
import { request } from '@umijs/max';

/** User login interface: POST /api/user/login */
export async function userLogin(
  body?: API.UserInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/user/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

/** New User Interface: POST /api/user/createUser */
export async function createUser(
  body?: API.UserInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/user/createUser`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

/** Update user interface: POST /api/user/updateUser */
export async function updateUser(
  body?: API.UserInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/user/updateUser`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

/** Delete user: POST /api/user/deleteUser */
export async function deleteUser(
  params: {
    /** id */
    userId: string;
  },
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/user/deleteUser`, {
    method: 'DELETE',
    params: { ...params },
    ...(options || {}),
  });
}

/** Current user information query interface: POST /api/user/queryUserInfo */
export async function queryUserInfo(
  body?: API.UserInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_T_>(`${BASE_URL}/api/user/queryUserInfo`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

/** Current user list query interface: POST /api/user/queryUserList */
export async function queryUserList(
  body: API.UserInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result>(`${BASE_URL}/api/user/queryUserList`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

/** Modify user roles: POST /api/user/changeUserRole */
export async function changeUserRole(
  body?: API.UserInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/user/changeUserRole`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

/** Enable or disable member accounts within the group: POST /api/user/changeUserStatus*/
export async function changeUserStatus(
  body?: API.UserInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/user/changeUserStatus`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

/** User changes password POST /api/user/changePassword*/
export async function changeUserPassword(
  body?: { userId: string; oldPassword: string; newPassword: string },
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/user/changePassword`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

/** Create AccessKey api/accessKey/createAccessKey */
export async function createAccessKey(
  body?: { [key: string]: any },
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(
    `${BASE_URL}/api/accessKey/createAccessKey`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      data: {
        ...body,
      },
      ...(options || {}),
    },
  );
}

/** Query List /api/accessKey/queryAccessKeyList */
export async function queryAccessKeyList(
  body?: API.BaseAccessInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_AccessInfo>(
    `${BASE_URL}/api/accessKey/queryAccessKeyList`,
    {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
      data: {
        ...body,
      },
      ...(options || {}),
    },
  );
}

/** Delete AccessKey DELETE /api/accessKey/deleteAccessKey */
export async function deleteAccessKey(
  params?: API.BaseAccessInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(
    `${BASE_URL}/api/accessKey/deleteAccessKey`,
    {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
      },
      data: {
        ...params,
      },
      ...(options || {}),
    },
  );
}

/** Add a note /api/accessKey/remarkAccessKey */
export async function remarkAccessKey(
  body?: API.BaseAccessInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(
    `${BASE_URL}/api/accessKey/remarkAccessKey`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      data: {
        ...body,
      },
      ...(options || {}),
    },
  );
}

/** register POST /api/user/register */
export async function register(
  body?: API.UserInfo,
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/user/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

/** Join tenant with invite code POST /api/user/joinTenant */
export async function joinTenant(
  body?: { inviteCode: string },
  options?: { [key: string]: any },
) {
  return request<API.Result_String_>(`${BASE_URL}/api/user/joinTenant`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      ...body,
    },
    ...(options || {}),
  });
}

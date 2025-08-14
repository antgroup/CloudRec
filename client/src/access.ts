export default (initialState: API.UserInfo) => {
  // Here, define the permissions in the project according to the initialization data and manage them uniformly
  // Reference Documents https://umijs.org/docs/max/access
  const isPlatformAdmin: boolean = initialState?.roleName === 'admin';
  const isTenantAdmin: boolean = initialState?.selectTenantRoleName === 'admin';
  const {
    username,
    userId,
    tenantName,
    roleName,
    selectTenantRoleName,
    gmtCreate,
    gmtModified,
    lastLoginTime,
  } = initialState;

  return {
    lastLoginTime,
    username,
    userId,
    tenantName,
    roleName,
    gmtCreate,
    gmtModified,
    isPlatformAdmin,
    isTenantAdmin,
  };
};

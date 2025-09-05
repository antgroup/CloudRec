package com.alipay.application.share.request.admin;


import lombok.Getter;
import lombok.Setter;

/*
 *@title changeTenantUserRoleRequest
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/24 15:33
 */
@Getter
@Setter
public class ChangeUserTenantRoleRequest {

    private String userId;

    private String roleName;

    private Long tenantId;
}

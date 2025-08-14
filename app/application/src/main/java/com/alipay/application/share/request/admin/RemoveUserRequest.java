package com.alipay.application.share.request.admin;


/*
 *@title RemoveUserRequest
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/25 18:09
 */


import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RemoveUserRequest {

    @NotNull(message = " userId 不能为空")
    private String userId;

    @NotNull(message = "tenantId不能为空")
    private Long tenantId;
}

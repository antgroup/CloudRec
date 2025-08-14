package com.alipay.application.share.request.admin;


import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

/*
 *@title JoinTenantRequest
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/25 17:10
 */
@Getter
@Setter
public class JoinTenantRequest {

    @NotEmpty(message = "The invite code cannot be empty")
    private String inviteCode;
}

package com.alipay.application.share.request.admin;


import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

/*
 *@title CreateInviteCodeRequest
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/25 17:22
 */

@Getter
@Setter
public class CreateInviteCodeRequest {

    @NotNull(message = "The tenant id cannot be null")
    private Long currentTenantId;
}

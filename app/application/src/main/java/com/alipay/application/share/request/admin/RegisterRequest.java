package com.alipay.application.share.request.admin;


import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

/*
 *@title RegisterRequest
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/25 14:29
 */
@Getter
@Setter
public class RegisterRequest {

    @NotEmpty(message = "The code cannot be empty")
    private String code;

    @NotEmpty(message = "The user id cannot be empty")
    private String userId;

    private String username;

    private String email;

    @NotEmpty(message = "The password cannot be empty")
    private String password;
}

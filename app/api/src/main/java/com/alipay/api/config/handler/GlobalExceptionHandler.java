/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alipay.api.config.handler;

import com.alibaba.fastjson.JSON;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.common.exception.BizException;
import com.alipay.common.exception.UserNoLoginException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(UserNoLoginException.class)
    public ApiResponse<String> exceptionHandler(UserNoLoginException e) {
        return new ApiResponse<>(ApiResponse.ACCESS_DENIED, "USER_NOT_LOGIN", e.getMsg());
    }

    @ExceptionHandler(BizException.class)
    public ApiResponse<String> exceptionHandler(BizException e) {
        log.error("Exception occurred!", e);
        return new ApiResponse<>(Integer.parseInt(e.getErrorCode().getCode()), e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ApiResponse<String> exceptionHandler(Exception e) {
        log.error("Exception occurred!", e);
        return new ApiResponse<>(ApiResponse.FAIL_CODE, e.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ApiResponse<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        log.error("Validation exception occurred!", ex);
        return new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), errors, JSON.toJSONString(errors));
    }
}

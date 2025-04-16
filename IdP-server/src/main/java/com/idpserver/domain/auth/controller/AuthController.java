package com.idpserver.domain.auth.controller;

import com.idpserver.domain.auth.dto.request.AuthRequestDto;
import com.idpserver.domain.auth.service.AuthService;
import com.idpserver.global.common.response.code.StatusCode;
import com.idpserver.global.common.response.dto.DataResponseDto;
import com.idpserver.global.common.response.exception.GeneralException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * @FileName AuthController.java
 * @author 신준섭
 * @Date 2025. 03. 31 ~
 * @version 1.0
 * @Description 진행중
 */
@RestController
@RequestMapping("/login")
public class AuthController {

    @Autowired
    AuthService authService;

    /**
     * @MethodName : login
     * @Author : 신준섭
     * @Date 2025. 03. 31
     * @Description : 로그인
     */
    @PostMapping("")
    public DataResponseDto<Object> login(@Validated AuthRequestDto.AuthLoginRequest authLoginRequest,
                                         BindingResult bindingResult,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {

        if (bindingResult.hasErrors()) {
            List<FieldError> list = bindingResult.getFieldErrors();
            for(FieldError error : list) {
                throw new GeneralException(StatusCode.BAD_REQUEST, error.getDefaultMessage());
            }
        }

        return authService.login(authLoginRequest, request ,response);
    }
}
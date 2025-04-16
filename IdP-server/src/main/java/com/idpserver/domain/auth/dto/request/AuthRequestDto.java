package com.idpserver.domain.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

public class AuthRequestDto {

    //TODO: 추후 정규식 논의 필요
    @Getter
    @Setter
    @ToString
    public static class AuthLoginRequest {

        @NotBlank(message="사용자 ID를 입력하세요.")
        private String username;

        @NotBlank(message="비밀번호를 입력하세요.")
        private String password;
    }
}

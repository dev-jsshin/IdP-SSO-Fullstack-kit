package com.idpserver.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.idpserver.security.utils.OAuthErrorResponseUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * OAuth2 인증/인가 과정에서 발생하는 인증 실패를 처리하는 커스텀 핸들러
 * 실패 시, 표준 OAuth2 에러 응답 형식에 따라 JSON 형태의 에러 메시지를 클라이언트에게 반환
 */
@Component
public class CustomOAuthErrorResponseHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 인증 실패 시 호출되는 메소드
     *
     * @param request   실패를 유발한 현재 HTTP 요청
     * @param response  클라이언트에게 보낼 HTTP 응답
     * @param exception 발생한 인증 관련 예외 객체
     * @throws IOException      응답 작성 중 I/O 오류 발생 시
     * @throws ServletException 서블릿 관련 오류 발생 시 (일반적으로는 발생하지 않음)
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        OAuth2Error error = OAuthErrorResponseUtils.extractOAuth2Error(exception);
        HttpStatus status = OAuthErrorResponseUtils.determineHttpStatus(error);
        String userFriendlyDescription = OAuthErrorResponseUtils.mapToUserFriendlyMessage(error);

        // HTTP 상태 코드 결정
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        // 응답 본문 생성
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", error.getErrorCode());
        errorResponse.put("error_description", userFriendlyDescription);

        // JSON 응답 작성
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        response.getWriter().flush();
    }
}
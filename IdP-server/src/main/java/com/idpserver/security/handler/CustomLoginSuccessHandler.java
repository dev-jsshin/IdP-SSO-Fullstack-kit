package com.idpserver.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component("CustomLoginSuccessHandler")
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        SavedRequest savedRequest = requestCache.getRequest(request, response);

        String redirectUrl = null;
        if (savedRequest != null) {
            redirectUrl = savedRequest.getRedirectUrl();

            // 사용 후 SavedRequest 제거
            requestCache.removeRequest(request, response);
        }

        // 2. JSON 응답 생성
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("success", true);
        responseBody.put("message", "Login successful");

        if (redirectUrl != null) {
            responseBody.put("redirectUrl", redirectUrl);
        } else {
            // SavedRequest가 없는 경우 (예: 직접 /login 호출 후 성공) 기본 성공 응답
            responseBody.put("redirectUrl", "/");
        }

        // 3. JSON 응답 작성
        objectMapper.writeValue(response.getWriter(), responseBody);
    }
}
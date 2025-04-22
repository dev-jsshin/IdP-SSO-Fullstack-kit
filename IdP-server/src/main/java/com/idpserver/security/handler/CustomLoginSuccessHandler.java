package com.idpserver.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.idpserver.security.service.OidcTokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component("CustomLoginSuccessHandler")
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(OidcTokenService.class);

    @Autowired
    private SecurityContextRepository securityContextRepository;

    private final RequestCache requestCache = new HttpSessionRequestCache();

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        // 1. 리디렉션 URL 처리
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        String redirectUrl = determineRedirectUrl(request, response, savedRequest);
        if (savedRequest != null) {
            // 사용 후 SavedRequest 제거 (선택적이지만 권장)
            requestCache.removeRequest(request, response);
            logger.info("[LoginSuccessHandler] SavedRequest 참조 성공. 캐시에서 제거되었습니다.");
        }

        // 2. Authentication 객체에 세션 ID 주입
        // ** 이 핸들러가 호출되는 시점에는 이미 인증이 완료된 상태.
        // ** Authentication 객체를 수정하고 SecurityContext에 다시 저장해야 함
        Authentication updatedAuthentication = injectSessionIdIntoAuthenticationDetails(request, authentication);

        // 3. 수정된 Authentication 객체를 SecurityContext에 저장
        // SecurityContextHolder 사용 및 Repository 통해 영속화
        saveAuthenticationToContext(request, response, updatedAuthentication);

        // 4. JSON 응답 생성 및 전송
        prepareAndSendJsonResponse(response, redirectUrl);
    }

    /**
     * 리디렉션할 URL을 결정, SavedRequest가 있으면 해당 URL을 사용하고, 없으면 기본 URL을 반환
     */
    private String determineRedirectUrl(HttpServletRequest request, HttpServletResponse response, SavedRequest savedRequest) {
        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            logger.info("[LoginSuccessHandler] SavedRequest가 존재합니다. {}", targetUrl);
            return targetUrl;
        } else {
            // SavedRequest가 없는 경우 기본 URL 반환
            // TODO: 기본 리디렉션 URL을 설정 파일 등에서 관리하도록 변경
            String defaultRedirectUrl = "/";
            logger.info("[LoginSuccessHandler] SavedRequest를 찾을 수 없습니다. 기본 URL로 리다이렉션 합니다. {}", defaultRedirectUrl);
            return defaultRedirectUrl;
        }
    }

    /**
     * 현재 세션 ID를 가져와 Authentication 객체의 details에 추가
     *
     * @param request        HttpServletRequest
     * @param authentication 원본 Authentication 객체
     * @return 세션 ID가 details에 추가된 (또는 원본) Authentication 객체
     */
    private Authentication injectSessionIdIntoAuthenticationDetails(HttpServletRequest request, Authentication authentication) {

        HttpSession session = request.getSession(false); // 세션이 없으면 새로 생성하지 않음
        String sessionId = (session != null) ? session.getId() : null;
        Map<String, Object> authDetails = new HashMap<>();

        if (sessionId != null) {
            authDetails.put("sessionId", sessionId);
            logger.info("[LoginSuccessHandler] sessionId가 존재합니다. [{}]", sessionId);

            if (authentication instanceof AbstractAuthenticationToken) {
                ((AbstractAuthenticationToken) authentication).setDetails(authDetails);
                logger.info("[LoginSuccessHandler] Authentication 객체에 details 설정 완료");
                return authentication;
            } else {
                logger.warn("[LoginSuccessHandler] Authentication 객체 타입({})은 details 설정 불가 (sessionId 정보 유실)", authentication.getClass().getName());
                return authentication; // 원본 객체 그대로 반환
            }
        } else {
            logger.warn("[LoginSuccessHandler] sessionId를 찾을 수 없습니다. Authentication details에 sessionId를 추가하지 못했습니다.");
            return authentication; // 원본 객체 그대로 반환
        }
    }

    /**
     * 주어진 Authentication 객체를 SecurityContext에 설정하고,
     * SecurityContextRepository를 사용하여 영속화
     */
    private void saveAuthenticationToContext(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        securityContextRepository.saveContext(context, request, response);
        logger.info("[LoginSuccessHandler] SecurityContext에 sessionId가 추가된 authentication 객체를 저장하였습니다.");
    }

    /**
     * 성공 응답을 JSON 형식으로 작성하여 클라이언트에게 전송
     */
    private void prepareAndSendJsonResponse(HttpServletResponse response, String redirectUrl) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("success", true);
        responseBody.put("message", "Login successful");
        responseBody.put("redirectUrl", redirectUrl);

        objectMapper.writeValue(response.getWriter(), responseBody);
    }
}
package com.idpserver.global.security.handler;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

import org.springframework.web.util.UriComponentsBuilder;

/**
 * ** RP -> IdP Logout 요청 처리 성공 시 호출되는 Custom Handler
 * -- 1. Back-Channel Notification Handler 호출
 * -- 2. 사용자 리디렉션 수행
 * LogoutSuccessHandler 인터페이스를 구현합니다.
 */
public class CustomOidcRpLogoutSuccessHandler implements AuthenticationSuccessHandler { // 인터페이스 변경!

    private static final Logger log = LoggerFactory.getLogger(CustomOidcRpLogoutSuccessHandler.class);

    private final CustomOidcBackChannelLogoutNotificationHandler backChannelLogoutHandler;

    private final RegisteredClientRepository registeredClientRepository;

    private final JwtDecoder jwtDecoder;

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private String defaultTargetUrl = "/"; // TODO: 기본 URL 설정 필요


    public CustomOidcRpLogoutSuccessHandler(CustomOidcBackChannelLogoutNotificationHandler backChannelLogoutHandler,
                                            RegisteredClientRepository registeredClientRepository,
    JwtDecoder jwtDecoder) {
        Assert.notNull(backChannelLogoutHandler, "backChannelLogoutHandler cannot be null");
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.backChannelLogoutHandler = backChannelLogoutHandler;
        this.registeredClientRepository = registeredClientRepository;
        this.jwtDecoder = jwtDecoder;
    }

    /**
     * LogoutFilter에 의해 호출되며, RP-Initiated Logout의 후처리를 수행
     * @param request 요청 객체
     * @param response 응답 객체
     * @param authentication 로그아웃 처리 완료 후의 Authentication 객체
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        // 1. 파라미터에서 정보 추출
        String idTokenHint = request.getParameter("id_token_hint");
        String postLogoutRedirectUri = request.getParameter("post_logout_redirect_uri");
        String state = request.getParameter("state");

        String subject = null;
        String sessionId = null;
        String clientId = null;

        log.info("[LogoutSuccessHandler] 로그아웃 성공 후 Notification 처리 시작");

        // 2. id_token_hint 파싱 및 검증
        if (StringUtils.hasText(idTokenHint)) {
            try {
                Jwt idToken = this.jwtDecoder.decode(idTokenHint);
                subject = idToken.getSubject();
                sessionId = idToken.getClaimAsString("sid");
                clientId = idToken.getAudience().stream().findFirst().orElse(null);

                log.info("[LogoutSuccessHandler] ID 토큰 파싱 성공. Subject: [{}], SessionId: [{}], ClientId: [{}]",
                        subject, sessionId, clientId);

            } catch (JwtException e) {
                throw createConfigurationError("잘못된 id_token_hint 입니다.");
            }
        } else {
            throw createConfigurationError("id_token_hint가 누락되었습니다.");
        }

        // 3. Back-Channel Logout 트리거 시도 (Back-Channel Logout Notification 실패 시에도 로그아웃 성공 처리)
        if (StringUtils.hasText(subject) && StringUtils.hasText(sessionId) && StringUtils.hasText(clientId)) {
            log.info("[LogoutSuccessHandler] 유효한 사용자 및 세션 정보 확인. Back-Channel Logout 트리거 시도");
            try {
                /* ---- Back-Channel Logout Notification Handler 호출 ---- */
                this.backChannelLogoutHandler.notifyBackChannelLogout(subject, sessionId, clientId);
                log.info("[LogoutSuccessHandler] Back-Channel Logout 알림 전송 완료");

            } catch (Exception e) {
                log.info("[LogoutSuccessHandler] Back-Channel Logout 트리거 중 오류 발생", e);
            }
        } else {
            log.info("[LogoutSuccessHandler] Back-Channel Logout 트리거에 필요한 정보(subject, sessionId, clientId)가 부족합니다.");
        }

        // 4. REDIRECT URL 결정 및 검증
        String targetUrl = determineAndValidateRedirectUrl(clientId, postLogoutRedirectUri, state);

        // 5. REDIRECT 수행
        log.info("[LogoutSuccessHandler] 모든 처리가 완료되어 사용자를 최종 REDIRECT_URL로 이동시킵니다: [{}]", targetUrl);
        this.redirectStrategy.sendRedirect(request, response, targetUrl);

        // TODO: 6. 세션 정보 삭제
    }

    /**
     * post_logout_redirect_uri 유효성을 검증하고 최종 REDIRECT_URI 결정
     *
     * @param clientId              ID 토큰에서 추출한 클라이언트 ID
     * @param postLogoutRedirectUri 요청 파라미터로 받은 URI
     * @param state                 요청 파라미터로 받은 state 값 (리디렉션 시 유지)
     * @return 유효한 리디렉션 URL (state 포함) 또는 기본 URL
     */
    private String determineAndValidateRedirectUrl(String clientId, String postLogoutRedirectUri, String state) {

        // 1. 필수 정보 확인
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(postLogoutRedirectUri)) {
            log.debug("[LogoutSuccessHandler] Client ID 또는 Post Logout Redirect URI가 제공되지 않아 기본 URL 사용.");
            return appendStateToUrl(this.defaultTargetUrl, state);
        }

        // 2. 클라이언트 정보 조회 및 URI 검증
        try {

            RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);

            if (registeredClient == null) {
                log.warn("[LogoutSuccessHandler] Post Logout Redirect URI 검증 실패: 클라이언트 ID [{}] 정보를 찾을 수 없습니다.", clientId);
                return appendStateToUrl(this.defaultTargetUrl, state);
            }

            // 3. URI 유효성 검증
            if (isValidPostLogoutRedirectUri(registeredClient, postLogoutRedirectUri)) {
                log.info("[LogoutSuccessHandler] 유효한 Post Logout Redirect URI 확인: {}", postLogoutRedirectUri);
                return appendStateToUrl(postLogoutRedirectUri, state);
            } else {
                log.warn("[LogoutSuccessHandler] 요청된 Post Logout Redirect URI [{}] 가 클라이언트 [{}] 에 등록되지 않았거나 유효하지 않습니다.", postLogoutRedirectUri, clientId);
                return appendStateToUrl(this.defaultTargetUrl, state);
            }

        } catch (OAuth2AuthenticationException e) {
            log.warn("[LogoutSuccessHandler] 클라이언트 [{}] 정보 조회 중 OAuth2 오류 발생: {}", clientId, e.getError().getDescription(), e);
            return appendStateToUrl(this.defaultTargetUrl, state);
        } catch (Exception e) {
            log.error("[LogoutSuccessHandler] Post Logout Redirect URI 검증 중 예상치 못한 오류 발생 (ClientId: {})", clientId, e);
            return appendStateToUrl(this.defaultTargetUrl, state);
        }
    }

    /**
     * 요청된 post_logout_redirect_uri가 RegisteredClient에 등록된 유효한 URI인지 확인합
     *
     * @param registeredClient 검증 대상 RegisteredClient 객체
     * @param requestedUri     요청된 post_logout_redirect_uri 문자열
     * @return 유효하면 true, 아니면 false
     */
    private boolean isValidPostLogoutRedirectUri(RegisteredClient registeredClient, String requestedUri) {
        if (registeredClient == null || !StringUtils.hasText(requestedUri)) {
            return false;
        }
        Set<String> registeredUris = registeredClient.getPostLogoutRedirectUris();

        return registeredUris != null && registeredUris.contains(requestedUri);
    }

    /**
     * URL에 state 파라미터를 추가
     */
    private String appendStateToUrl(String url, String state) {
        if (StringUtils.hasText(state)) {
            return UriComponentsBuilder.fromUriString(url)
                    .queryParam("state", state)
                    .build().toUriString();
        }
        return url;
    }

    /**
     * 클라이언트 설정 오류 발생 시 OAuth2AuthenticationException을 생성하는 헬퍼 메서드.
     * @param message 사용자에게 전달될 수 있는 오류 설명
     * @return 생성된 OAuth2AuthenticationException 객체
     */
    private OAuth2AuthenticationException createConfigurationError(String message) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, message, null));
    }

}
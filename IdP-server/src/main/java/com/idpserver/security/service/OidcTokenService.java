package com.idpserver.security.service;

import org.springframework.stereotype.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

@Service
public class OidcTokenService {

    private static final Logger logger = LoggerFactory.getLogger(OidcTokenService.class);

    /**
     * ID 토큰에 'sid' 클레임을 추가
     * @param context JWT 인코딩 컨텍스트
     */
    public void addSidClaimToIdToken(JwtEncodingContext context) {

        if (!OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            return; // ID 토큰이 아니면 아무 작업도 하지 않음
        }

        logger.info("[OidcTokenService] id token 생성 context 감지. Authentication details에서 SID 조회 시도");

        Authentication authentication = context.getPrincipal();
        String sessionId = extractSessionId(authentication);

        if (sessionId != null) {
            try {
                String sessionIdHash = calculateSha256Hash(sessionId);
                logger.info("[OidcTokenService] 원본 sessionId [{}]의 SHA-256 해시값 [{}] 계산 완료.", sessionId, sessionIdHash);

                context.getClaims().claim("sid", sessionIdHash);
                logger.info("[OidcTokenService] 'sid' 클레임에 세션 ID 해시값 추가 완료.");

            } catch (NoSuchAlgorithmException e) {
                logger.error("[OidcTokenService] 세션 ID 해시 계산 중 오류 발생 (알고리즘 없음): {}", e.getMessage(), e);
            } catch (Exception e) {
                logger.error("[OidcTokenService] 세션 ID 해시 계산 또는 클레임 추가 중 예외 발생: {}", e.getMessage(), e);
            }
        } else {
            logger.info("[OidcTokenService] 유효한 `sessionId` 를 찾지 못해 'sid' 클레임 추가 불가");
        }
    }

    /**
     * Authentication 객체에서 세션 ID를 추출
     * @param authentication 인증 객체
     * @return 추출된 세션 ID 또는 null
     */
    private String extractSessionId(Authentication authentication) {
        if (authentication == null) {
            logger.info("[OidcTokenService] Authentication 객체를 찾을 수 없습니다.");
            return null;
        }

        Object detailsObject = authentication.getDetails();
        String sessionId = null;

        if (detailsObject instanceof Map) {

            @SuppressWarnings("unchecked")
            Map<String, Object> details = (Map<String, Object>) detailsObject;
            sessionId = (String) details.get("sessionId");

            if(sessionId != null){
                logger.info("[OAuth2TokenCustomizer] Authentication details에서 `sessionId` [{}] 발견", sessionId);
            } else {
                logger.info("[OAuth2TokenCustomizer] Authentication details에 `sessionId` 키가 없거나 값이 null입니다.");
            }

        } else {
            logger.info("[OAuth2TokenCustomizer] Authentication details 객체가 Map 타입이 아닙니다. (타입: {})",
                    (detailsObject != null ? detailsObject.getClass().getName() : "null"));
        }
        return sessionId;
    }


    /**
     * 입력 문자열의 SHA-256 해시값을 계산하고 Base64 URL-safe 인코딩으로 반환
     * @param input 원본 문자열 (세션 ID)
     * @return Base64 URL-safe 인코딩된 SHA-256 해시값
     * @throws NoSuchAlgorithmException SHA-256 알고리즘을 찾을 수 없을 때
     */
    private String calculateSha256Hash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}

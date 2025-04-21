package com.idpserver.security.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

/**
 * OAuth2 관련 오류 응답 처리를 위한 유틸리티 클래스
 * OAuth2Error 추출, HTTP 상태 코드 결정, 사용자 메시지 정의
 */
public final class OAuthErrorResponseUtils {

    private static final Logger log = LoggerFactory.getLogger(OAuthErrorResponseUtils.class);

    private OAuthErrorResponseUtils() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * 전달된 AuthenticationException에서 OAuth2Error 객체를 추출
     *
     * @param exception 처리할 인증 예외 객체
     * @return 추출되거나 생성된 OAuth2Error 객체
     */
    public static OAuth2Error extractOAuth2Error(AuthenticationException exception) {
        if (exception instanceof OAuth2AuthenticationException) {
            OAuth2Error nestedError = ((OAuth2AuthenticationException) exception).getError();

            if (nestedError != null) {
                return nestedError;
            }
        }
        return new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                "시스템 처리 중 예상치 못한 오류가 발생했습니다.", null); // 기본 메시지 개선 가능
    }

    /**
     * 주어진 OAuth2Error의 에러 코드를 기반으로 적절한 HTTP 상태 코드 결정
     *
     * @param error HTTP 상태 코드를 결정할 OAuth2Error 객체
     * @return 결정된 HttpStatus 객체
     */
    public static HttpStatus determineHttpStatus(OAuth2Error error) {
        String errorCode = error.getErrorCode();

        if (OAuth2ErrorCodes.INVALID_CLIENT.equals(errorCode) ||
                OAuth2ErrorCodes.INVALID_GRANT.equals(errorCode) ||
                OAuth2ErrorCodes.INVALID_REQUEST.equals(errorCode) ||
                OAuth2ErrorCodes.INVALID_SCOPE.equals(errorCode) ||
                OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE.equals(errorCode) ||
                OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE.equals(errorCode)) {
            return HttpStatus.BAD_REQUEST; // 400 Bad Request
        } else if (OAuth2ErrorCodes.UNAUTHORIZED_CLIENT.equals(errorCode)) {
            return HttpStatus.UNAUTHORIZED; // 401 Unauthorized
        } else if (OAuth2ErrorCodes.ACCESS_DENIED.equals(errorCode)) {
            return HttpStatus.FORBIDDEN; // 403 Forbidden
        }

        return HttpStatus.INTERNAL_SERVER_ERROR;
    }

    /**
     * OAuth2Error 및 원본 예외를 기반으로 사용자 친화적인 오류 메시지를 생성
     *
     * @param error             처리할 OAuth2Error 객체
     * @return 사용자에게 보여줄 오류 메시지 문자열
     */
    public static String mapToUserFriendlyMessage(OAuth2Error error) {

        String defaultMessage = error.getDescription();
        String description = error.getDescription();

        if (OAuth2ErrorCodes.INVALID_REQUEST.equals(error.getErrorCode())) {
            if(description != null && description.contains("OAuth 2.0 Parameter")) {
                if (description.contains("client_id")) {
                    return "해당 client_id는 유효하지 않거나 누락되었습니다.";
                } else if (description.contains("redirect_uri")) {
                    return "해당 redirect_uri는 유효하지 않거나 누락되었습니다.";
                } else if (description.contains("response_type")) {
                    return "해당 response_type은 유효하지 않거나 누락되었습니다.";
                } else if (description.contains("code")) {
                    return "해당 code는 유효하지 않거나 누락되었습니다.";
                } else if (description.contains("grant_type")) {
                    return "해당 grant_type은 유효하지 않거나 누락되었습니다.";
                }
            }
        } else if (OAuth2ErrorCodes.INVALID_GRANT.equals(error.getErrorCode())) {
            return "해당 인가 정보는 유효하지 않습니다.";
        } else if (OAuth2ErrorCodes.INVALID_SCOPE.equals(error.getErrorCode())) {
            return "해당 scope는 유효하지 않거나 허용되지 않습니다.";
        } else if (OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE.equals(error.getErrorCode())) {
            return "해당 grant_type은 유효하지 않거나 누락되었습니다.";
        }

        return defaultMessage;
    }
}
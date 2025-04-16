package com.idpserver.global.security.service;

import com.idpserver.global.common.utils.FlagUtils;
import com.idpserver.global.common.utils.ParserUtils;
import com.idpserver.global.entity.client.TmClientScope;
import com.idpserver.global.entity.client.TmClientSetting;
import com.idpserver.global.entity.client.TnClient;
import com.idpserver.global.entity.client.TnScope;
import com.idpserver.global.security.repository.TmClientScopeRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * TnClient 엔티티를 RegisteredClient 객체로 변환하고 관련 로직을 처리하는 서비스 클래스
 */
@Service
@RequiredArgsConstructor
public class RegisteredClientService {

    private static final Logger log = LoggerFactory.getLogger(RegisteredClientService.class);

    private static final String OPENID_SCOPE = "openid";                     // OIDC 필수 스코프
    private static final long DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 3600L;      // 기본 Access Token 유효 시간 (1시간)
    private static final long DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 86400L;    // 기본 Refresh Token 유효 시간 (1일)
    private static final long DEFAULT_AUTH_CODE_TTL_SECONDS = 300L;          // 기본 Authorization Code 유효 시간 (5분)
    private static final SignatureAlgorithm DEFAULT_ID_TOKEN_SIGNATURE_ALGORITHM = SignatureAlgorithm.RS256;
    private final TmClientScopeRepository tmClientScopeRepository;

    /**
     * 유효성이 검증된 TnClient 엔티티를 RegisteredClient 객체로 변환
     * 이 메서드는 TnClient 객체가 존재한다고 가정 (앞단에서 기본적인 검증 진행)
     *
     * @param tnClient 유효성이 검증된 TnClient 객체
     * @return 생성된 RegisteredClient 객체
     * @throws OAuth2AuthenticationException 필수 설정 누락 또는 유효하지 않은 설정 값 발견 시
     */
    public RegisteredClient buildRegisteredClient(TnClient tnClient) {
        String clientIdForLogging = tnClient.getClientId();
        log.info("RegisteredClient 변환 시작: CLINET_ID [{}]", clientIdForLogging);

        TmClientSetting tmClientSetting = Optional.ofNullable(tnClient.getTmClientSetting())
                .orElseThrow(() -> createConfigurationError(clientIdForLogging,"클라이언트 설정 정보가 없습니다."));

        try {
            // 1. 클라이언트 인증 방식 설정 (필수)
            Set<ClientAuthenticationMethod> clientAuthenticationMethods = buildClientAuthenticationMethods(tmClientSetting, clientIdForLogging);
            // 2. 허용된 인가 부여 타입 설정 (필수)
            Set<AuthorizationGrantType> authorizationGrantTypes = buildAuthorizationGrantTypes(tmClientSetting, clientIdForLogging);
            // 3. Redirect URI 설정 (Authorization Code Grant Type 사용 시 필수)
            Set<String> redirectUris = buildRedirectUris(tmClientSetting, authorizationGrantTypes, clientIdForLogging);
            // 4. Post Logout Redirect URI 설정 (선택)
            Set<String> postLogoutRedirectUris = buildPostLogoutRedirectUris(tmClientSetting);
            // 5. Scope 설정 (OIDC 사용 시 'openid' 필수)
            Set<String> scopes = buildScopes(tnClient, clientIdForLogging);
            // 6. 클라이언트별 세부 설정 (PKCE, Consent 등) 및 JWT 인증 방식 관련 설정
            ClientSettings clientSettings = buildClientSettings(tmClientSetting, clientAuthenticationMethods, clientIdForLogging);
            // 7. 토큰 관련 설정 (유효 기간, 리프레시 토큰 재사용 여부, ID 토큰 서명 알고리즘 등)
            TokenSettings tokenSettings = buildTokenSettings(tmClientSetting, clientIdForLogging);

            // --- 최종 RegisteredClient 객체 생성 ---
            RegisteredClient registeredClient = RegisteredClient.withId(String.valueOf(tnClient.getClientSn()))
                    .clientId(tnClient.getClientId())
                    .clientSecret(tnClient.getClientSecret()) // TODO: 비밀번호 인코딩 필요 (PasswordEncoder 주입)
                    .clientName(tnClient.getClientNm())
                    .clientIdIssuedAt(tnClient.getRegDt() != null ? tnClient.getRegDt().toInstant() : Instant.now())
                    .clientAuthenticationMethods(methods -> methods.addAll(clientAuthenticationMethods))
                    .authorizationGrantTypes(grants -> grants.addAll(authorizationGrantTypes))
                    .redirectUris(uris -> uris.addAll(redirectUris))
                    .postLogoutRedirectUris(uris -> uris.addAll(postLogoutRedirectUris))
                    .scopes(s -> s.addAll(scopes))
                    .clientSettings(clientSettings)
                    .tokenSettings(tokenSettings)
                    .build();

            log.info("RegisteredClient 객체 변환 완료. CLINET_ID: [{}]", registeredClient.getClientId());
            return registeredClient;

        } catch (OAuth2AuthenticationException e) {
            log.error("RegisteredClient 변환 중 클라이언트 설정 오류 발생: CLINET_ID [{}]. Error: {}",
                    clientIdForLogging, e.getError().getDescription(), e);
            throw e;
        } catch (Exception e) {
            log.error("RegisteredClient 변환 중 예상치 못한 오류 발생: CLINET_ID [{}]", clientIdForLogging, e);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "클라이언트 정보 처리 중 내부 서버 오류가 발생했습니다.", null), e);
        }
    }

    private Set<ClientAuthenticationMethod> buildClientAuthenticationMethods(TmClientSetting setting, String clientId) {
        Set<ClientAuthenticationMethod> methods = ParserUtils.parseCommaSeparatedString(setting.getClientAuthenticationMethods(), ClientAuthenticationMethod::new);
        if (methods.isEmpty()) {
            throw createConfigurationError(clientId,"클라이언트 인증 방식이 설정되지 않았습니다.");
        }
        return methods;
    }

    private Set<AuthorizationGrantType> buildAuthorizationGrantTypes(TmClientSetting setting, String clientId) {
        Set<AuthorizationGrantType> grants = ParserUtils.parseCommaSeparatedString(setting.getAuthorizedGrantTypes(), AuthorizationGrantType::new);
        if (grants.isEmpty()){
            throw createConfigurationError(clientId, "허가된 인가 부여 타입이 설정되지 않았습니다.");
        }
        return grants;
    }

    private Set<String> buildRedirectUris(TmClientSetting setting, Set<AuthorizationGrantType> grants, String clientId) {
        Set<String> uris = ParserUtils.parseCommaSeparatedString(setting.getRedirectUris(), Function.identity());
        if (grants.contains(AuthorizationGrantType.AUTHORIZATION_CODE) && uris.isEmpty()) {
            throw createConfigurationError(clientId,"redirect_uri가 필요합니다.");
        }
        return uris;
    }

    private Set<String> buildPostLogoutRedirectUris(TmClientSetting setting) {
        return ParserUtils.parseCommaSeparatedString(setting.getPostLogoutRedirectUris(), Function.identity());
    }

    private Set<String> buildScopes(TnClient tnClient, String clientId) {
        Set<String> scopes = getScopesForClient(tnClient);
        if (!scopes.contains(OPENID_SCOPE)) {
            throw createConfigurationError(clientId, "'openid' Scope 정보를 찾을 수 없습니다.");
        }
        return scopes;
    }

    private ClientSettings buildClientSettings(TmClientSetting setting, Set<ClientAuthenticationMethod> authMethods, String clientId) {

        ClientSettings.Builder builder = ClientSettings.builder()
                // 인가 승인 화면 요구 여부
                .requireAuthorizationConsent(FlagUtils.isYesIgnoreCase(setting.getRequireAuthorizationConsent()))
                // PKCE 요구 여부
                .requireProofKey(FlagUtils.isYesIgnoreCase(setting.getRequireProofKey()));

        // 1. private_key_jwt 관련 설정 적용 (JWK Set URL)
        configureJwkSetUrlIfNeeded(builder, setting, authMethods, clientId);
        // 2. Token Endpoint 서명 알고리즘 설정 적용 (private_key_jwt, client_secret_jwt 공통 로직)
        configureTokenEndpointSigningAlgorithm(builder, setting, authMethods, clientId);
        // 3. Backchannel Logout 설정 적용
        configureBackchannelLogout(builder, setting, clientId);

        return builder.build();
    }

    /**
     * private_key_jwt 인증 방식일 경우 JWK Set URL 설정을 적용합니다. (필수)
     */
    private void configureJwkSetUrlIfNeeded(ClientSettings.Builder builder, TmClientSetting setting, Set<ClientAuthenticationMethod> authMethods, String clientId) {

        if (authMethods.contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
            if (StringUtils.hasText(setting.getJwkSetUrl())) {
                builder.jwkSetUrl(setting.getJwkSetUrl());
                log.info("CLIENT_ID [{}] 인증방식 'private_key_jwt'에 대해 JWK Set URL 설정: {}", clientId, setting.getJwkSetUrl());
            } else {
                throw createConfigurationError(clientId, "'private_key_jwt' 인증 방식을 사용하는 클라이언트는 JWK Set URL 설정이 필수입니다.");
            }
        }
    }

    /**
     * JWT 기반 인증 방식(private_key_jwt, client_secret_jwt)에 대해
     * Token Endpoint 서명 알고리즘 설정을 검증하고 적용
     */
    private void configureTokenEndpointSigningAlgorithm(ClientSettings.Builder builder, TmClientSetting setting, Set<ClientAuthenticationMethod> authMethods, String clientId) {

        String algorithmString = setting.getTokenEndpointAuthenticationSigningAlgorithm();
        boolean isPrivateKeyJwt = authMethods.contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        boolean isClientSecretJwt = authMethods.contains(ClientAuthenticationMethod.CLIENT_SECRET_JWT);

        if (StringUtils.hasText(algorithmString)) {
            try {
                SignatureAlgorithm algorithm = SignatureAlgorithm.from(algorithmString);
                String algName = algorithm.getName();

                if (isPrivateKeyJwt) {
                    // private_key_jwt: 비대칭 알고리즘(RS*, ES*, PS*) 검증
                    boolean isAsymmetric = algName.startsWith("RS") || algName.startsWith("ES") || algName.startsWith("PS");
                    if (!isAsymmetric) {
                        throw createConfigurationError(clientId, "'private_key_jwt' 인증 방식에는 비대칭키 서명 알고리즘(RS*, ES*, PS*)만 사용 가능합니다.");
                    }
                    builder.tokenEndpointAuthenticationSigningAlgorithm(algorithm);
                    log.info("CLIENT_ID [{}] 'private_key_jwt'에 대해 Token Endpoint 서명 알고리즘 설정: {}", clientId, algName);

                } else if (isClientSecretJwt) {
                    // client_secret_jwt: 대칭 알고리즘(HS*) 검증
                    boolean isSymmetricHmac = algName.startsWith("HS");
                    if (!isSymmetricHmac) {
                        throw createConfigurationError(clientId, "'client_secret_jwt' 인증 방식에는 대칭키 서명 알고리즘(HS*)만 사용 가능합니다.");
                    }
                    builder.tokenEndpointAuthenticationSigningAlgorithm(algorithm);
                    log.info("CLIENT_ID [{}] 'client_secret_jwt'에 대해 Token Endpoint 서명 알고리즘 설정: {}", clientId, algName);

                }
            } catch (IllegalArgumentException e) {
                throw createConfigurationError(clientId, "유효하지 않은 Token Endpoint 서명 알고리즘 값입니다: " + algorithmString);
            }
        } else {
            if (isPrivateKeyJwt) {
                log.info("CLIENT_ID [{}] 인증 방식 'private_key_jwt'에 Token Endpoint 서명 알고리즘이 지정되지 않았습니다. 서버 기본값 또는 JWK 'alg' 파라미터를 사용할 수 있습니다.", clientId);
            } else if (isClientSecretJwt) {
                builder.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.from("HS256"));
                log.info("CLIENT_ID [{}] 인증 방식 'client_secret_jwt'에 Token Endpoint 서명 알고리즘이 지정되지 않았습니다. 기본값(보통 HS256)을 사용합니다.", clientId);
            }
        }
    }

    /**
     * Backchannel Logout 관련 설정을 적용합니다.
     */
    private void configureBackchannelLogout(ClientSettings.Builder builder, TmClientSetting setting, String clientId) {

        boolean required = FlagUtils.isYesIgnoreCase(setting.getBackchannelLogoutSessionRequired());

        if (required) {
            builder.setting("backchannel_logout_session_required", FlagUtils.isYesIgnoreCase(setting.getBackchannelLogoutSessionRequired()));
            log.info("CLIENT_ID [{}] Backchannel Logout Session Required 설정: {}", clientId, required);

            if (StringUtils.hasText(setting.getBackchannelLogoutUri())) {
                builder.setting("backchannel_logout_uri", setting.getBackchannelLogoutUri());
                log.info("CLIENT_ID [{}] Backchannel Logout URI 설정: {}", clientId, setting.getBackchannelLogoutUri());
            } else if (FlagUtils.isYesIgnoreCase(setting.getBackchannelLogoutSessionRequired())) {
                builder.setting("backchannel_logout_session_required", false);
                log.info("CLIENT_ID [{}] 'backchannel_logout_session_required'가 true로 설정되었지만, 'backchannel_logout_uri'가 없습니다. (Session Required 강제 False 처리)", clientId);
            }
        }
    }

    private TokenSettings buildTokenSettings(TmClientSetting setting, String clientId) {
        TokenSettings.Builder builder = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofSeconds(Optional.ofNullable(setting.getAccessTokenLifeSpan()).orElse(DEFAULT_ACCESS_TOKEN_TTL_SECONDS)))
                .refreshTokenTimeToLive(Duration.ofSeconds(Optional.ofNullable(setting.getRefreshTokenLifeSpan()).orElse(DEFAULT_REFRESH_TOKEN_TTL_SECONDS)))
                .authorizationCodeTimeToLive(Duration.ofSeconds(Optional.ofNullable(setting.getAuthorizationCodeLifeSpan()).orElse(DEFAULT_AUTH_CODE_TTL_SECONDS)))
                .reuseRefreshTokens(FlagUtils.isYesIgnoreCase(setting.getReuseRefreshTokens()));

        SignatureAlgorithm idTokenAlg = DEFAULT_ID_TOKEN_SIGNATURE_ALGORITHM;
        if (StringUtils.hasText(setting.getIdTokenSignatureAlgorithm())) {
            try {
                idTokenAlg = SignatureAlgorithm.from(setting.getIdTokenSignatureAlgorithm());
            } catch (IllegalArgumentException e) {
                log.warn("클라이언트 [{}]의 ID 토큰 서명 알고리즘 [{}]이(가) 유효하지 않아 기본값({})을 사용합니다.",
                        clientId, setting.getIdTokenSignatureAlgorithm(), DEFAULT_ID_TOKEN_SIGNATURE_ALGORITHM.getName());
            }
        } else {
            log.warn("클라이언트 [{}]의 ID 토큰 서명 알고리즘이 설정되지 않아 기본값({})을 사용합니다.",
                    clientId, DEFAULT_ID_TOKEN_SIGNATURE_ALGORITHM.getName());
        }
        builder.idTokenSignatureAlgorithm(idTokenAlg);

        return builder.build();
    }

    private Set<String> getScopesForClient(TnClient tnClient) {
        if (tnClient == null || tnClient.getClientSn() == null) return Collections.emptySet();
        try {
            List<TmClientScope> clientScopes = tmClientScopeRepository.findByClientSn(tnClient.getClientSn());
            if (clientScopes == null || clientScopes.isEmpty()) {
                log.debug("No scopes found for client SN: {}", tnClient.getClientSn());
                return Collections.emptySet();
            }
            Set<String> scopeNames = clientScopes.stream()
                    .map(TmClientScope::getTnScope).filter(Objects::nonNull)
                    .map(TnScope::getScopeNm).filter(StringUtils::hasText)
                    .collect(Collectors.toSet());
            log.debug("Found scopes for client SN [{}]: {}", tnClient.getClientSn(), scopeNames);
            return scopeNames;
        } catch (Exception e) {
            log.error("DB 조회 중 오류 발생: 클라이언트 SN [{}]의 스코프 조회 실패", tnClient.getClientSn(), e);
            // Scope 조회 실패 시 오류를 던질 수도 있음
            // throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "스코프 정보를 조회하는 중 오류 발생", null), e);
            return Collections.emptySet(); // 현재는 빈 Set 반환
        }
    }

    // --- OAuth2 예외 생성 헬퍼 ---
    private OAuth2AuthenticationException createConfigurationError(String clientId, String message) {
        log.warn("클라이언트 설정 오류: CLIENT_ID [{}], Message [{}]", clientId, message);

        return new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, message, null));
    }
}
package com.idpserver.global.security.repository;

import com.idpserver.global.common.response.code.StatusCode;
import com.idpserver.global.common.response.exception.GeneralException;
import com.idpserver.global.common.utils.FlagUtils;
import com.idpserver.global.common.utils.IpUtils;
import com.idpserver.global.common.utils.ParserUtils;
import com.idpserver.global.entity.client.TmClientScope;
import com.idpserver.global.entity.client.TmClientSetting;
import com.idpserver.global.entity.client.TnClient;
import com.idpserver.global.entity.client.TnScope;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class CustomRegisteredClientRepository implements RegisteredClientRepository {

    private static final Logger log = LoggerFactory.getLogger(CustomRegisteredClientRepository.class);

    // --- 상수 정의 ---
    private static final String CLIENT_STATUS_ACTIVE = "1";
    private static final String OPENID_SCOPE = "openid";
    private static final long DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 3600L;      // 1시간
    private static final long DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 86400L;  // 1일
    private static final long DEFAULT_AUTH_CODE_TTL_SECONDS = 300L;       // 10분
    private static final SignatureAlgorithm DEFAULT_ID_TOKEN_SIGNATURE_ALGORITHM = SignatureAlgorithm.RS256;

    @Autowired
    private TnClientRepository clientRepository;

    @Autowired
    private TmClientScopeRepository tmClientScopeRepository;

    /**
     * CLIENT_SN(PK)을 기반으로 RegisteredClient를 찾기.
     *
     * @param identifier CLIENT_SN
     * @return 조회된 RegisteredClient 객체
     * @throws GeneralException 클라이언트를 찾을 수 없거나 유효하지 않은 경우
     */
    @Override
    public RegisteredClient findById(String identifier) {

        String clientIp = IpUtils.getClientIpAddress();
        log.info("------ 클라이언트 DB 조회 CLIENT_SN: [{}] IP: [{}]", identifier, clientIp);

        if (!StringUtils.hasText(identifier)) {
            throw createConfigurationError("client_id를 찾을 수 없습니다.");
        }

        Optional<TnClient> clientOptional = clientRepository.findByClientSn(Long.valueOf(identifier));
        if (clientOptional.isEmpty()) {
            throw new GeneralException(StatusCode.BAD_REQUEST, "client_id를 찾을 수 없습니다.");
        }

        TnClient tnClient = clientOptional.get();

        return tnClientToRegisteredClient(tnClient, clientIp);
    }

    /**
     * CLIENT_ID를 기반으로 RegisteredClient를 찾기.
     *
     * @param clientId CLIENT_ID
     * @return 조회된 RegisteredClient 객체
     * @throws GeneralException 클라이언트를 찾을 수 없거나 유효하지 않은 경우
     */
    @Override
    public RegisteredClient findByClientId(String clientId) {

        String clientIp = IpUtils.getClientIpAddress();
        log.info("------ 클라이언트 DB 조회 CLIENT_ID: [{}] IP: [{}]", clientId, clientIp);

        if (!StringUtils.hasText(clientId)) {
            throw createConfigurationError("client_id를 찾을 수 없습니다.");
        }

        Optional<TnClient> clientOptional = clientRepository.findByClientId(clientId);
        if (clientOptional.isEmpty()) {
            throw createConfigurationError("client_id를 찾을 수 없습니다.");
        }

        TnClient tnClient = clientOptional.get();

        return tnClientToRegisteredClient(tnClient, clientIp);
    }


    private RegisteredClient tnClientToRegisteredClient(TnClient tnClient, String clientIp) {

        log.info("RegisteredClient 변환 대상 CLIENT_SN: [{}] IP: [{}]", tnClient.getClientSn(), clientIp);

        try {
            // 클라이언트 상태 확인 ('1' 정상 상태만 유효)
            if (!CLIENT_STATUS_ACTIVE.equals(tnClient.getClientStatus())) {
                log.info("클라이언트의 상태가 정상이 아닙니다. CLIENT_ID: [{}] STATUS: [{}]", tnClient.getClientId(), tnClient.getClientStatus());
                throw createConfigurationError("client_id를 찾을 수 없습니다.");
            }

            TmClientSetting tmClientSetting = Optional.ofNullable(tnClient.getTmClientSetting())
                    .orElseThrow(() -> createConfigurationError("클라이언트 설정 정보가 없습니다."));

            /* 1. Authentication Methods 설정 */
            Set<ClientAuthenticationMethod> clientAuthenticationMethods =
                    ParserUtils.parseCommaSeparatedString(tmClientSetting.getClientAuthenticationMethods(), ClientAuthenticationMethod::new);
            if (clientAuthenticationMethods.isEmpty()) {
                throw createConfigurationError("client 인증 방식이 설정되지 않았습니다.");
            }

            /* 2. Grant Types 설정 */
            Set<AuthorizationGrantType> authorizationGrantTypes =
                    ParserUtils.parseCommaSeparatedString(tmClientSetting.getAuthorizedGrantTypes(), AuthorizationGrantType::new);

            if (authorizationGrantTypes.isEmpty()){
                throw createConfigurationError("허가된 인가 부여 타입이 설정되지 않았습니다.");
            }

            /* 3. Redirect URIs 설정 */
            Set<String> redirectUris = ParserUtils.parseCommaSeparatedString(tmClientSetting.getRedirectUris(), Function.identity());
            // 특정 Grant Type (예: authorization_code) 사용 시 Redirect URI는 필수일 수 있음
            if (authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE) && redirectUris.isEmpty()) {
                throw createConfigurationError("Redirect URI가 설정되지 않았습니다.");
            }

            /* 4. Post Logout Redirect URIs 설정 */
            Set<String> postLogoutRedirectUris = ParserUtils.parseCommaSeparatedString(tmClientSetting.getPostLogoutRedirectUris(), Function.identity());

            /* 5. Scopes 설정 */
            Set<String> scopes = getScopesForClient(tnClient);
            if (!scopes.contains(OPENID_SCOPE)) { // OIDC 사용 시 'openid' 스코프는 필수
                throw createConfigurationError("'openid' Scope 정보를 찾을 수 없습니다.");
            }

            /* 6. Client Settings 설정 */
            ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
                    .requireAuthorizationConsent(FlagUtils.isYesIgnoreCase(tmClientSetting.getRequireAuthorizationConsent()))
                    .requireProofKey(FlagUtils.isYesIgnoreCase(tmClientSetting.getRequireProofKey()));

            /* 7. JWK SET URL 설정 */
            if (StringUtils.hasText(tmClientSetting.getJwkSetUrl())) {
                clientSettingsBuilder.jwkSetUrl(tmClientSetting.getJwkSetUrl());
            }

            /* 8. Token Endpoint Authentication Signing Algorithm 설정 */
            if (StringUtils.hasText(tmClientSetting.getTokenEndpointAuthenticationSigningAlgorithm())) {
                try {
                    // 문자열로부터 JwsAlgorithm 객체 생성
                    clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(
                            SignatureAlgorithm.from(tmClientSetting.getTokenEndpointAuthenticationSigningAlgorithm())
                    );
                } catch (IllegalArgumentException e) {
                    log.info("클라이언트 [{}]의 Token Endpoint 서명 알고리즘 [{}] 변환 실패", tnClient.getClientId(), tmClientSetting.getTokenEndpointAuthenticationSigningAlgorithm(), e);
                    throw createConfigurationError("유효하지 않은 Token Endpoint 서명 알고리즘입니다.");
                }
            }

            /* 9. Backchannel Logout 설정 */
            if (StringUtils.hasText(tmClientSetting.getBackchannelLogoutUri())) {
                clientSettingsBuilder.setting("backchannel_logout_uri", tmClientSetting.getBackchannelLogoutUri());
            }
            clientSettingsBuilder.setting("backchannel_logout_session_required", tmClientSetting.getBackchannelLogoutSessionRequired());
            ClientSettings clientSettings = clientSettingsBuilder.build();

            /* 10. Token Settings 설정 */
            TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofSeconds(Optional.ofNullable(tmClientSetting.getAccessTokenLifeSpan()).orElse(DEFAULT_ACCESS_TOKEN_TTL_SECONDS)))
                    .refreshTokenTimeToLive(Duration.ofSeconds(Optional.ofNullable(tmClientSetting.getRefreshTokenLifeSpan()).orElse(DEFAULT_REFRESH_TOKEN_TTL_SECONDS)))
                    .authorizationCodeTimeToLive(Duration.ofSeconds(Optional.ofNullable(tmClientSetting.getAuthorizationCodeLifeSpan()).orElse(DEFAULT_AUTH_CODE_TTL_SECONDS)))
                    .reuseRefreshTokens(FlagUtils.isYesIgnoreCase(tmClientSetting.getReuseRefreshTokens()));
            TokenSettings tokenSettings = tokenSettingsBuilder.build();

            /* 11. ID Token Signature Algorithm 설정 */
            if (StringUtils.hasText(tmClientSetting.getIdTokenSignatureAlgorithm())) {
                try {
                    tokenSettingsBuilder.idTokenSignatureAlgorithm(
                            SignatureAlgorithm.from(tmClientSetting.getIdTokenSignatureAlgorithm())
                    );
                } catch (IllegalArgumentException e) {
                    // ID 토큰 알고리즘은 필수이므로 기본값 설정
                    log.info("클라이언트 [{}]의 ID 토큰 서명 알고리즘 [{}] 변환 실패", tnClient.getClientId(), tmClientSetting.getIdTokenSignatureAlgorithm(), e);
                    tokenSettingsBuilder.idTokenSignatureAlgorithm(DEFAULT_ID_TOKEN_SIGNATURE_ALGORITHM);
                }
            } else {
                // ID 토큰 알고리즘은 필수이므로 기본값 설정
                tokenSettingsBuilder.idTokenSignatureAlgorithm(DEFAULT_ID_TOKEN_SIGNATURE_ALGORITHM);
                log.info("클라이언트 [{}]의 ID 토큰 서명 알고리즘이 설정되지 않아 기본값(RS256)을 사용합니다.", tnClient.getClientId());
            }

            /* 12. 최종 RegisteredClient 반환 */
            RegisteredClient registeredClient = RegisteredClient.withId(String.valueOf(tnClient.getClientSn())) // 또는 UUID 기반 ID 사용
                    .clientId(tnClient.getClientId())
                    .clientSecret(tnClient.getClientSecret())
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

            log.info("RegisteredClient 객체 생성 완료. ClientId: [{}]", registeredClient.getClientId());

            return registeredClient;
        } catch (OAuth2AuthenticationException e) {
            log.warn("RegisteredClient 객체 생성 중 클라이언트 설정 오류 발생. ClientId: [{}]", tnClient.getClientId(), e);
            throw e;
        } catch (Exception e) {
            log.error("RegisteredClient 객체 생성 중 예상치 못한 오류 발생. ClientId: [{}]", tnClient.getClientId(), e);

            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                            "클라이언트 정보를 처리하는 중 서버 오류가 발생했습니다. 관리자에게 문의 바랍니다.", null), e); // 원인 예외 포함
        }
    }

    /**
     * TnClient 엔티티에 연결된 Scope 목록에서 Scope 이름(String)들을 추출
     *
     * @param tnClient Scope를 조회할 TnClient 엔티티
     * @return Scope 이름 문자열의 Set (조회 실패 또는 Scope 없으면 빈 Set 반환)
     */
    private Set<String> getScopesForClient(TnClient tnClient) {

        try {
            List<TmClientScope> clientScopes = tmClientScopeRepository.findByClientSn(tnClient.getClientSn());

            // 1. Scope 존재 여부 확인
            if (clientScopes == null || clientScopes.isEmpty()) {
                return Collections.emptySet();
            }

            // 2. 각 TmClientScope 객체에서 TnScope 객체를 가져와 이름 추출
            Set<String> scopeNames = clientScopes.stream()
                    .map(TmClientScope::getTnScope)
                    .filter(Objects::nonNull)
                    .map(TnScope::getScopeNm)
                    .filter(StringUtils::hasText)
                    .collect(Collectors.toSet());
            return scopeNames;
        } catch (Exception e) {
            return Collections.emptySet();
        }
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



    @Override
    public void save(RegisteredClient registeredClient) {}
}
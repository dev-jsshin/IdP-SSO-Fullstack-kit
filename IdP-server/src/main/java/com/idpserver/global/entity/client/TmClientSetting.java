package com.idpserver.global.entity.client;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.DynamicUpdate;

@Entity
@Table(name = "TM_CLIENT_SETTING")
@Data
@Builder
@DynamicUpdate
@AllArgsConstructor
public class TmClientSetting {

    /* 클라이언트 고유일련번호 */
    @Id
    @Column(name = "CLIENT_SN", nullable = false)
    private Long clientSn;

    // TmClientSetting(One) -> TnClient(One)
    @OneToOne(fetch = FetchType.LAZY)
    @MapsId // clientSn 필드 값을 tnClient 엔티티의 ID 값으로 매핑
    @JoinColumn(name = "CLIENT_SN", referencedColumnName = "CLIENT_SN")
    @ToString.Exclude
    private TnClient tnClient;

    /* 클라이언트 인증 방식 */
    @Column(name = "CLIENT_AUTHENTICATION_METHODS",nullable = false)
    private String clientAuthenticationMethods;

    /* 허가된 인증방식 */
    @Column(name = "AUTHORIZED_GRANT_TYPES", nullable = false)
    private String authorizedGrantTypes;

    /* 로그인 후 리다이렉션 URI 목록 */
    @Column(name = "REDIRECT_URIS")
    private String redirectUris;

    /* 로그아웃 후 리다이렉션 URI 목록 */
    @Column(name = "POST_LOGOUT_REDIRECT_URIS")
    private String postLogoutRedirectUris;

    /* 인가 동의 요구 여부 */
    @Column(name = "REQUIRE_AUTHORIZATION_CONSENT", nullable = false)
    private String requireAuthorizationConsent;

    /* PKCE 요구 여부 */
    @Column(name = "REQUIRE_PROOF_KEY", nullable = false)
    private String requireProofKey;

    /* 클라이언트 공개키 경로 */
    @Column(name = "JWK_SET_URL")
    private String jwkSetUrl;

    /* 토큰 엔드포인트 인증 서명 알고리즘 */
    @Column(name = "TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM")
    private String tokenEndpointAuthenticationSigningAlgorithm;

    /* 엑세스 토큰 유효 기간 */
    @Column(name = "ACCESS_TOKEN_LIFE_SPAN", nullable = false)
    private Long accessTokenLifeSpan;

    /* 리프레시 토큰 유효 기간 */
    @Column(name = "REFRESH_TOKEN_LIFE_SPAN", nullable = false)
    private Long refreshTokenLifeSpan;

    /* 리프레시 토큰 재사용 여부 */
    @Column(name = "REUSE_REFRESH_TOKENS", nullable = false)
    private String reuseRefreshTokens;

    /* ID 토큰 서명 알고리즘 */
    @Column(name = "ID_TOKEN_SIGNATURE_ALGORITHM", nullable = false)
    private String idTokenSignatureAlgorithm;

    /* 인가 코드 유효기간 */
    @Column(name = "AUTHORIZATION_CODE_LIFE_SPAN", nullable = false)
    private Long authorizationCodeLifeSpan;

    /* Back-Channel Logout URI */
    @Column(name = "BACKCHANNEL_LOGOUT_URI")
    private String backchannelLogoutUri;

    /* Back-Channel Logout 세션 요구 여부 */
    @Column(name = "BACKCHANNEL_LOGOUT_SESSION_REQUIRED", nullable = false)
    private String backchannelLogoutSessionRequired;

    public TmClientSetting() {

    }
}
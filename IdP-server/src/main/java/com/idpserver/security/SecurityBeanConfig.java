package com.idpserver.security;

import com.idpserver.security.service.OidcTokenService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Spring Security(DefaultSecurityConfig.java) 및 OAuth2 Authorization Server(AuthorizationServerConfig.java) Bean 정의
 */
@Configuration
public class SecurityBeanConfig {

    @Autowired
    private OidcTokenService oidcTokenService;

    @Value("${security.oauth2.authorizationserver.issuer}")
    private String issuerUri;

    @Value("${auth.paths.logout-url}")
    private String sloLogoutUrl;

    /**
     * Spring Security의 인증 처리를 담당하는 AuthenticationManager Bean 생성
     * @param authenticationConfiguration Spring Boot 자동 설정을 통해 주입되는 인증 설정 객체
     * @return AuthenticationManager 인스턴스
     * @throws Exception 빈 생성 중 예외 발생 시
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * OAuth2 인가 정보(Authorization Grant, 토큰 등)를 저장하고 관리하는 Bean 생성
     * TODO: In-Memory 사용 중. (서버 재시작 시 데이터 소멸) -> DB 저장 방식으로 변경 필요
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * OIDC ID 토큰 생성 시 'sid'(세션 ID 해시) 클레임을 추가하는 Bean 생성
     * @return ID 토큰에 'sid' 클레임을 추가하는 로직이 포함된 {@link OAuth2TokenCustomizer} 인스턴스
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenSidCustomizer() {
        return context -> oidcTokenService.addSidClaimToIdToken(context);
    }

    /**
     * JWT 서명 및 검증에 사용될 비대칭 키(RSA) 쌍을 포함하는 JWKSource Bean 생성
     * TODO: 고정된 키를 사용하도록 변경 필요 (테스트 용으로만 사용)
     * @return JWKSource 인스턴스
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * RSA 키 쌍을 생성하는 Helper 메서드
     * @return 생성된 KeyPair 객체
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * JWT를 생성하고 서명하는 JwtEncoder Bean 생성
     * @param jwkSource JWK 키 소스
     * @return JwtEncoder 인스턴스
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * 수신된 JWT의 서명을 검증하고 디코딩하는 JwtDecoder Bean 생성
     * jwkSource를 사용하여 공개키 가져옴
     * @param jwkSource JWK 키 소스
     * @return JwtDecoder 인스턴스
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 사용자 비밀번호 관련 PasswordEncoder Bean 생성 (BCrypt 알고리즘 사용)
     * @return PasswordEncoder 인스턴스
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * SecurityContext를 저장하고 로드하는 Bean 생성 (세션 기반)
     * TODO: 추후 DB 기반으로 변경 필요
     * @return SecurityContextRepository 인스턴스
     */
    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    /**
     * HttpSession 생성 및 소멸 Event를 감지하여 Spring Context에 전달하는 Bean 생성
     * @return HttpSessionEventPublisher 인스턴스
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    // TODO: 추후 설정파일에서 추출 방식 변경
    /**
     * OAuth2 Authorization Server의 전반적인 설정을 정의하는 Bean 생성 (예: Issuer URI, 엔드포인트 경로 등)
     * @return AuthorizationServerSettings 인스턴스
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuerUri)
                .oidcLogoutEndpoint(sloLogoutUrl)
                // .oidcClientRegistrationEndpoint("/connect/register")
                // .oidcUserInfoEndpoint("/userinfo")
                .build();
    }
}

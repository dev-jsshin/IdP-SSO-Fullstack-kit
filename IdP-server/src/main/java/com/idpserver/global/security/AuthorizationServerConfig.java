package com.idpserver.global.security;

import com.idpserver.global.security.handler.CustomOAuthErrorResponseHandler;
import com.idpserver.global.security.handler.CustomOidcRpLogoutSuccessHandler;
import com.idpserver.global.security.handler.CustomOidcBackChannelLogoutNotificationHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import lombok.RequiredArgsConstructor;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    @Autowired
    private CustomOidcBackChannelLogoutNotificationHandler customOidcBackChannelLogoutNotificationHandler;

    @Autowired
    private CustomOAuthErrorResponseHandler customOAuthErrorResponseHandler;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Bean
    @Order(1) // 가장 높은 우선순위
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // 1. Authorization Server 설정자 생성
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        // 2. OIDC 관련 설정 적용
        authorizationServerConfigurer
                .oidc(oidc -> oidc
                        .logoutEndpoint(logout -> logout
                                .logoutResponseHandler(customOidcRpLogoutSuccessHandler())
                        )
                        .userInfoEndpoint(withDefaults())
                        .clientRegistrationEndpoint(withDefaults())
                );

        // 3. 적용될 엔드포인트 Matcher 가져오기
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http
                // 4. 해당 엔드포인트에만 이 필터 체인 적용
                .securityMatcher(endpointsMatcher)
                // 5. 생성 및 설정된 Configurer를 HttpSecurity에 적용
                .with(authorizationServerConfigurer, configurer -> {
                    configurer
                            .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                                            .errorResponseHandler(customOAuthErrorResponseHandler)
                            )
                            .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                            .errorResponseHandler(customOAuthErrorResponseHandler)
                    );
                })
                // 6. 나머지 보안 설정 적용
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(withDefaults()))
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    /**
     * RP-Initiated Logout 요청 처리가 성공한 후 호출될 커스텀 LogoutSuccessHandler 빈을 생성합니다.
     * 이 빈은 Back-Channel 핸들러와 RegisteredClientRepository를 주입받습니다.
     * @return 커스텀 LogoutSuccessHandler 인스턴스
     */
    @Bean
    public AuthenticationSuccessHandler customOidcRpLogoutSuccessHandler() {
        return new CustomOidcRpLogoutSuccessHandler(
                this.customOidcBackChannelLogoutNotificationHandler,
                this.registeredClientRepository,
                this.jwtDecoder
        );
    }
}
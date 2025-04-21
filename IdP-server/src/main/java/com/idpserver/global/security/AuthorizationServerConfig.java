package com.idpserver.global.security;

import com.idpserver.global.config.cors.CorsConfig;
import com.idpserver.global.security.handler.CustomOAuthErrorResponseHandler;
import com.idpserver.global.security.handler.CustomOidcRpLogoutSuccessHandler;
import com.idpserver.global.security.handler.CustomOidcBackChannelLogoutNotificationHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
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


    @Autowired
    @Qualifier("CustomLoginSuccessHandler") // SecurityBeanConfig 등에 정의된 빈
    private AuthenticationSuccessHandler CustomLoginSuccessHandler; // 로그인 성공 핸들러

    @Autowired
    private CorsConfig corsConfig;

    @Bean
    @Order(1) // 가장 높은 우선순위
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // 1. Authorization Server 설정자 생성
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        RequestMatcher loginProcessingMatcher = new AntPathRequestMatcher("/login", "POST");
        RequestMatcher oidcLogoutMatcher = new AntPathRequestMatcher("/logout", "GET");
        RequestMatcher authorizeMatcher = new AntPathRequestMatcher("/oauth2/authorize", "GET");

        RequestMatcher authorizationServerAndLoginMatcher = new OrRequestMatcher(
                endpointsMatcher,          // OAuth2/OIDC 표준 엔드포인트 포함
                loginProcessingMatcher,    // 로그인 처리 경로
                oidcLogoutMatcher,         // OIDC 로그아웃 경로
                authorizeMatcher           // 인가 엔드포인트 명시적 포함
        );

        // 2. OIDC 관련 설정 적용
        authorizationServerConfigurer
                .oidc(oidc -> oidc
                        .logoutEndpoint(logout -> logout
                                .logoutResponseHandler(customOidcRpLogoutSuccessHandler())
                        )
                        .userInfoEndpoint(withDefaults())
                        .clientRegistrationEndpoint(withDefaults())
                );

        // 3. 엔드포인트 설정
        http
                .securityMatcher(authorizationServerAndLoginMatcher)
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("http://localhost:5173/login"), // <<<--- 로그인 페이지 경로 지정
                                new MediaTypeRequestMatcher(org.springframework.http.MediaType.TEXT_HTML)
                        )
                )
                .formLogin(form -> form
                        .loginProcessingUrl("/login")
                        .successHandler(CustomLoginSuccessHandler)
                        .permitAll()
                )
                .sessionManagement(session -> session
                        .sessionFixation(fixation -> fixation
                                .migrateSession() // 세션 속성 유지하며 ID 변경
                        )
                )
                // 4. 생성 및 설정된 Configurer를 HttpSecurity에 적용
                .with(authorizationServerConfigurer, configurer -> {
                    configurer
                            .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                                    .errorResponseHandler(customOAuthErrorResponseHandler)
                            )
                            .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                    .errorResponseHandler(customOAuthErrorResponseHandler)
                            );
                })
                // 5. 나머지 보안 설정 적용
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(withDefaults()))
                .cors(cors -> cors.configurationSource(corsConfig.corsConfigurationSource()))
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
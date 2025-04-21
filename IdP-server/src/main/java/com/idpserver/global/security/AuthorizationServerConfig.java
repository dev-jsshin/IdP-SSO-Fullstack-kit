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
import org.springframework.web.cors.CorsConfigurationSource;

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
    @Qualifier("loginSuccessHandler") // SecurityBeanConfig 등에 정의된 빈
    private AuthenticationSuccessHandler loginSuccessHandler; // 로그인 성공 핸들러

    @Autowired
    private CorsConfig corsConfig;
    @Autowired private CorsConfigurationSource corsConfigurationSource;
    @Bean
    @Order(1) // 가장 높은 우선순위
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {


        // 1. Authorization Server 설정자 생성
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        // ===>>> 2. 로그인 처리 경로(/login POST)와 OIDC 로그아웃 경로(/logout GET) 매처 추가 <<<===
        RequestMatcher loginProcessingMatcher = new AntPathRequestMatcher("/login", "POST");
        RequestMatcher oidcLogoutMatcher = new AntPathRequestMatcher("/logout", "GET");

        // ===>>> 3. 모든 관련 경로를 처리하도록 securityMatcher 구성 <<<===
        RequestMatcher authorizationServerAndLoginMatcher = new OrRequestMatcher(
                endpointsMatcher,          // OAuth2/OIDC 표준 엔드포인트
                loginProcessingMatcher,    // 로그인 처리 경로
                oidcLogoutMatcher          // OIDC 로그아웃 경로
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

        // 3. 적용될 엔드포인트 Matcher 가져오기

        http
                // 4. 해당 엔드포인트에만 이 필터 체인 적용
                .securityMatcher(authorizationServerAndLoginMatcher)
                .exceptionHandling(exceptions -> exceptions
                        // HTML 요청(브라우저 등)일 경우 로그인 페이지로 리디렉션
                        .defaultAuthenticationEntryPointFor(
                                new CorsAwareLoginUrlAuthenticationEntryPoint("http://localhost:5173/login", corsConfigurationSource, "http://localhost:5173"),
                                new MediaTypeRequestMatcher(org.springframework.http.MediaType.TEXT_HTML)
                        )
                )
                // ===>>> formLogin() 설정 추가 <<<===
                .formLogin(form -> form
                        // 로그인 페이지는 React 앱 URL 이지만, 실제 처리 URL은 /login (POST)
                        // loginPage() 설정은 EntryPoint가 처리하므로 여기서는 불필요할 수 있음
                        // .loginPage("http://localhost:5173/login")
                        // Spring Security가 /login POST 요청을 처리하도록 함 (기본값)
                        .loginProcessingUrl("/login")
                        // 인증 성공 시 SavedRequestAware 핸들러 사용
                        .successHandler(loginSuccessHandler)
                        // 필요시 실패 핸들러 설정
                        // .failureUrl("/login?error")
                        .permitAll() // 로그인 처리 URL 자체는 허용해야 함 (POST /login)
                )
                // ===>>> 세션 관리 설정: 여기에 위치해야 함! <<<===
                .sessionManagement(session -> session
                        .sessionFixation(fixation -> fixation
                                .migrateSession() // 세션 속성 유지하며 ID 변경
                        )
                )
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
                        .requestMatchers("/login", "/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(withDefaults()))
                .cors(cors -> cors.configurationSource(corsConfig.corsConfigurationSource())) // CORS 설정;
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
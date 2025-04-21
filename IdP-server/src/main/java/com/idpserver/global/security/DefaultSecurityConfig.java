package com.idpserver.global.security;

import com.idpserver.global.config.cors.CorsConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

@Configuration
public class DefaultSecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private CorsConfig corsConfig;

    @Autowired
    @Qualifier("loginSuccessHandler") // SecurityBeanConfig 등에 정의된 빈
    private AuthenticationSuccessHandler loginSuccessHandler; // 로그인 성공 핸들러

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // ... authorizeHttpRequests (로그인 페이지, 정적 리소스 permitAll) ...
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/error", "/", "/index.html", "/static/**").permitAll()
                        .anyRequest().authenticated()
                )
                // ===>>> formLogin 설정 필수 <<<===
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login") // POST /login 처리
                        .successHandler(loginSuccessHandler) // 로그인 성공 핸들러
                        .permitAll()
                )
                // ... logout, sessionManagement, csrf, userDetailsService, cors ...
                .logout(logout -> logout // 웹 로그아웃 (옵션)
                        .logoutUrl("/api/logout")
                        // ...
                        .permitAll()
                )
                .sessionManagement(session -> session.sessionFixation(fix -> fix.migrateSession()))
                .csrf(AbstractHttpConfigurer::disable)
                .userDetailsService(userDetailsService)
                .cors(cors -> cors.configurationSource(corsConfig.corsConfigurationSource()));

        return http.build();
    }
}
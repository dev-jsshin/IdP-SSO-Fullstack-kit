package com.idpserver.config.cors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;
import java.util.List;

/**
 * CORS 설정을 정의하는 Bean
 * @return CorsConfigurationSource
 */
@Configuration
public class CorsConfig {

    @Value("${auth.base-url}")
    private String authBaseUrl;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // --- 허용할 Origin 설정 ---
        configuration.setAllowedOrigins(List.of(authBaseUrl));

        // --- 허용할 HTTP 메서드 ---
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH")); // 필요한 메서드만 허용 가능

        // --- 허용할 HTTP 헤더 ---
        configuration.setAllowedHeaders(List.of("*"));

        // --- Credentials (쿠키, Authorization 헤더 등) 허용 여부 ---
        configuration.setAllowCredentials(true);

        // --- Preflight 요청 캐시 시간 (초 단위) ---
        configuration.setMaxAge(3600L); // 1시간

        // --- 모든 경로에 대해 위 설정 적용 ---
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
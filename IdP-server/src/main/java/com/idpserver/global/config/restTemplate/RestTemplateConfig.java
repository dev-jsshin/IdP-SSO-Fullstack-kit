package com.idpserver.global.config.restTemplate;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.web.client.RestTemplate;
import java.time.Duration;

@Configuration
@EnableAsync // 비동기 메소드 실행 활성화
public class RestTemplateConfig { // 또는 다른 설정 클래스

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        // 타임아웃 설정 등 추가 구성 가능
        return builder
//                .setConnectTimeout(Duration.ofSeconds(5)) // 연결 타임아웃
//                .setReadTimeout(Duration.ofSeconds(10))   // 읽기 타임아웃
                .build();
    }
}
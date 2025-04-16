package com.idpserver.global.common.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * IP 주소 관련 유틸리티 메소드를 제공하는 클래스.
 */
public class IpUtils {

    private static final Logger log = LoggerFactory.getLogger(IpUtils.class);
    private static final String UNKNOWN_IP = "unknown";

    private IpUtils() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * 현재 HTTP 요청 컨텍스트에서 클라이언트 IP 주소를 가져오기
     *
     * @return 클라이언트 IP 주소 문자열. 요청 컨텍스트가 없거나 IP를 찾을 수 없으면 "unknown"을 반환
     */
    public static String getClientIpAddress() {
        HttpServletRequest request = getCurrentHttpRequest();

        if (request == null) {
            log.info("IP 주소를 가져올 수 없습니다. (요청 컨텍스트 외부에서 호출됨)");
            return UNKNOWN_IP;
        }

        try {
            String ip = request.getHeader("X-Forwarded-For");
            if (isValidIp(ip)) {
                return ip.split(",")[0].trim();
            }

            // 다른 프록시 관련 헤더 확인
            ip = request.getHeader("Proxy-Client-IP");
            if (isValidIp(ip)) return ip;

            ip = request.getHeader("WL-Proxy-Client-IP");
            if (isValidIp(ip)) return ip;

            ip = request.getHeader("HTTP_CLIENT_IP");
            if (isValidIp(ip)) return ip;

            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
            if (isValidIp(ip)) return ip;

            ip = request.getRemoteAddr();
            if (isValidIp(ip)) return ip;

        } catch (Exception e) {
            log.info("IP 주소를 가져오는 중 오류 발생 URI: [{}] {}", request.getRequestURI(), e.getMessage());
        }

        return UNKNOWN_IP;
    }

    /**
     * RequestContextHolder를 통해 현재 스레드의 HttpServletRequest 객체 가져오기
     * 웹 요청 컨텍스트 외부에서 호출되면 null을 반환
     *
     * @return 현재 HttpServletRequest 객체 또는 null
     */
    private static HttpServletRequest getCurrentHttpRequest() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            if (attributes != null) {
                return attributes.getRequest();
            }
        } catch (IllegalStateException e) {
            log.debug("HttpServletRequest를 가져올 수 없습니다. (요청 컨텍스트 외부에서 호출됨)");
        } catch (Exception e) {
            log.info("IP 주소를 가져오는 중 오류 발생 [{}]", e.getMessage());
        }
        return null;
    }

    /**
     * 주어진 IP 문자열이 유효한지 (null이 아니고, 길이가 있고, "unknown"이 아닌지) 확인
     * 실제 IP 형식 유효성 검사(예: IPv4, IPv6)는 수행 X
     *
     * @param ip 확인할 IP 문자열
     * @return 유효하면 true, 아니면 false
     */
    private static boolean isValidIp(String ip) {
        return StringUtils.hasText(ip) && !UNKNOWN_IP.equalsIgnoreCase(ip);
    }

}

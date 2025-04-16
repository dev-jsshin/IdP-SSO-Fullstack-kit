package com.idpserver.domain.auth.service;

import com.idpserver.domain.auth.dto.request.AuthRequestDto;
import com.idpserver.global.common.response.code.StatusCode;
import com.idpserver.global.common.response.dto.DataResponseDto;
import com.idpserver.global.common.response.exception.GeneralException;
import com.idpserver.global.security.service.CustomUserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final CustomUserDetailsService customUserDetailsService;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    /**
     * 인증 성공 시 SecurityContext에 인증 정보를 저장
     * `id_token` 에 'sid' 클레임을 추가하기 위해 세션 ID를 Authentication 객체의 details에 포함
     *
     * @param authLoginRequest 로그인 요청 DTO (username, password 포함)
     * @param request          HttpServletRequest 객체 (세션 접근용)
     * @param response         HttpServletResponse 객체 (세션 저장용)
     * @return 로그인 성공 또는 실패에 대한 응답 DTO
     * @throws GeneralException 인증 실패 또는 내부 오류 발생 시
     * `id_token` 생성이 로그인 프로세스와 분리된 비동기 스레드에서 발생할 경우를 대비하여 (스레드 컨텍스트 불일치 이슈)
     * 로그인 프로세스 내에서 `sessionId` 를 `Authentication` 객체의 `details`에 저장하는 방식
     *
     */
    public DataResponseDto<Object> login(AuthRequestDto.AuthLoginRequest authLoginRequest, HttpServletRequest request, HttpServletResponse response) {

        try {
            // 1. 사용자 정보 로드 (UserDetails 객체 확보)
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(authLoginRequest.getUsername());

            // 2. AuthenticationManager 에게 전달할 인증 토큰 생성
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    authLoginRequest.getUsername(),
                    authLoginRequest.getPassword()
            );

            // 3. AuthenticationManager를 통해 실제 인증 수행
            Authentication authenticatedAuthentication = authenticationManager.authenticate(authenticationToken);


            // 4. 세션 ID를 Authentication 객체의 'details'에 추가 (`id_token` 'sid' 클레임 준비)
            HttpSession session = request.getSession();
            String sessionId = (session != null) ? session.getId() : null;
            Map<String, Object> authDetails = new HashMap<>();

            if (sessionId != null) {
                authDetails.put("sessionId", sessionId);
                logger.info("[LOGIN] Authentication details에 sessionId [{}] 추가", sessionId);
            } else {
                logger.info("[LOGIN] Authentication details에 sessionId를 추가하지 못했습니다.");
            }

            // 5. SecurityContext에 저장할 최종 Authentication 객체 준비
            Authentication finalAuthentication;
            if (authenticatedAuthentication instanceof AbstractAuthenticationToken) {
                ((AbstractAuthenticationToken) authenticatedAuthentication).setDetails(authDetails);
                finalAuthentication = authenticatedAuthentication;
                logger.info("[LOGIN] Authentication 객체에 details 설정 완료");
            } else {
                finalAuthentication = new UsernamePasswordAuthenticationToken(
                        authenticatedAuthentication.getPrincipal(),
                        null,
                        authenticatedAuthentication.getAuthorities()
                );
                // TODO: 커스텀 Authentication 객체 구현 고려
                logger.info("[LOGIN] Authentication 객체 타입({})은 details 설정 불가 (sessionId 정보 유실)", authenticatedAuthentication.getClass());
            }

            // 6.SecurityContext에 인증 정보 저장 및 Repository 통해 영속화
            //   TODO: 추후 DB에 세션 정보 저장하는 방식으로 변경 필요
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(finalAuthentication); // details 포함된 객체 저장
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, request, response);

            logger.info("[LOGIN] User '{}' logged in successfully.", finalAuthentication.getName());
            return DataResponseDto.of(StatusCode.OK, "로그인 성공");

        } catch (Exception e) {
            logger.error("[LOGIN] AuthService.login {}", e.getMessage());
            throw new GeneralException(StatusCode.INTERNAL_ERROR, e.getMessage());
        }
    }
}

package com.idpserver.global.security.handler;

import com.idpserver.global.entity.client.TmClientSetting;
import com.idpserver.global.entity.client.TnClient;
import com.idpserver.global.security.repository.TnClientRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.*;

/**
 * ** RP에게 Back-Channel 방식으로 Logout Notification 을 위한 Custom Logout Handler
 * 'sub' 클레임만을 사용하여 로그아웃 대상 사용자를 식별
 * 'sid' 클레임을 사용하지않더라도 OIDC 사양을 위반하는 것이 아님 (구현이 쉽고 효율적이며, 많이 사용되는 방식)
 */
@Component
public class CustomOidcBackChannelLogoutNotificationHandler {
    private static final Logger logger = LoggerFactory.getLogger(CustomOidcBackChannelLogoutNotificationHandler.class);

    private static final String OIDC_BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private final AuthorizationServerSettings authorizationServerSettings;
    private final JwtEncoder jwtEncoder;
    private final RestTemplate restTemplate;

    @Autowired
    private TnClientRepository tnClientRepository;

    /**
     * @param registeredClientRepository 클라이언트 정보 저장소
     * @param authorizationServerSettings IdP 설정 (issuer 등)
     * @param jwtEncoder JWT 인코더 (Logout Token 서명)
     */
    @Autowired
    public CustomOidcBackChannelLogoutNotificationHandler(RegisteredClientRepository registeredClientRepository,
                                                          AuthorizationServerSettings authorizationServerSettings,
                                                          JwtEncoder jwtEncoder) {

        // 주입된 빈 null이 아닌지 확인
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(authorizationServerSettings, "authorizationServerSettings cannot be null");
        Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");

        this.authorizationServerSettings = authorizationServerSettings;
        this.jwtEncoder = jwtEncoder;
        this.restTemplate = new RestTemplate();

        logger.info("[LOGOUT-NOTIFICATION] CustomOidcBackChannelLogoutNotificationHandler init 성공");
    }

    /**
     * 주어진 사용자 및 세션 정보를 기반으로 Back-Channel 로그아웃 알림 전송
     *
     * @param subject   로그아웃하는 사용자의 Subject 식별자 (ID 토큰의 'sub')
     * @param sessionId 로그아웃하는 세션의 ID (ID 토큰의 'sid')
     * @param clientId  로그아웃을 시작한 클라이언트의 ID (ID 토큰의 'aud') - 로깅 및 추적용
     */
    public void notifyBackChannelLogout(String subject, String sessionId, @Nullable String clientId) {

        logger.info("[Back-Channel Logout] 로그아웃 알림 프로세스 시작. Subject: [{}], SessionId: [{}], Initiating ClientId: [{}]",
                subject, sessionId, clientId != null ? clientId : "N/A");

        // 1. 필수 정보 유효성 검사
        if (!StringUtils.hasText(subject)) {
            logger.warn("[Back-Channel Logout] 필수 정보 'subject'가 누락되었습니다.");
            return;
        }
        if (!StringUtils.hasText(sessionId)) {
            logger.warn("[Back-Channel Logout] 필수 정보 'sessionId'가 누락되었습니다. SID 기반 로그아웃을 진행할 수 없습니다.");
            return;
        }

        // 2. Back-Channel Logout URI가 설정된 모든 클라이언트 조회 (활성 상태)
        Iterable<TnClient> targetTnClients = findActiveClientsWithBackChannelLogoutUri();
        if (!targetTnClients.iterator().hasNext()) {
            logger.info("[Back-Channel Logout] 로그아웃 알림을 보낼 대상 클라이언트가 없습니다.");
            return;
        }

        int successCount = 0;
        int failureCount = 0;

        // 3. 각 대상 클라이언트에게 Logout Token 전송
        for (TnClient tnClient : targetTnClients) {
            String targetClientId = tnClient.getClientId();

            String backChannelLogoutUri = Optional.ofNullable(tnClient.getTmClientSetting())
                    .map(TmClientSetting::getBackchannelLogoutUri)
                    .filter(StringUtils::hasText)
                    .orElse(null);

            try {
                logger.debug("[Back-Channel Logout] 클라이언트 [{}]에게 보낼 로그아웃 토큰 생성을 시작", targetClientId);
                String logoutToken = createLogoutToken(targetClientId, subject, sessionId);
                logger.debug("[Back-Channel Logout] 클라이언트 [{}] 로그아웃 토큰 생성 완료.", targetClientId);

                sendBackChannelLogoutRequest(targetClientId, backChannelLogoutUri, logoutToken);

                successCount++;

            } catch (OAuth2AuthenticationException configEx) {
                logger.info("[Back-Channel Logout] 클라이언트 [{}] 처리 중 설정 오류 발생 (RegisteredClient 생성 실패): {}", targetClientId, configEx.getError().getDescription(), configEx);
                failureCount++;
            } catch (JwtEncodingException jwtEx) {
                logger.info("[Back-Channel Logout] 클라이언트 [{}]의 로그아웃 토큰 생성 실패: {}", targetClientId, jwtEx.getMessage(), jwtEx);
                failureCount++;
            } catch (Exception e) {
                logger.info("[Back-Channel Logout] 클라이언트 [{}] 처리 중 오류 발생: {}", targetClientId, e.getMessage(), e);
                failureCount++;
            }
        }
        logger.info("[Back-Channel Logout] Subject: [{}], SessionId: [{}]에 대한 Back-Channel 로그아웃 알림 전송 완료. 성공: {}, 실패: {}",
                subject, sessionId, successCount, failureCount);
    }


    /**
     * Logout Token을 생성 ('sid' 및 'sub' 클레임 포함).
     *
     * @param clientId 대상 클라이언트
     * @param subject 로그아웃하는 사용자 Subject
     * @param sid 사용할 세션 ID
     * @return 서명된 Logout Token 문자열
     * @throws JwtEncodingException JWT 인코딩 중 오류 발생 시
     */
    private String createLogoutToken(String clientId, String subject, String sid) throws JwtEncodingException {
        Instant issuedAt = Instant.now();

        Instant expiresAt = issuedAt.plusSeconds(120); // TODO: 로그아웃 토큰 시간 DB 설정 필요

        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer(this.authorizationServerSettings.getIssuer())
                .subject(subject) // sub 클레임 필수 포함
                .audience(List.of(clientId)) // 대상 클라이언트 ID
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString()) // JTI (JWT ID)
                .claim("events", Map.of(OIDC_BACKCHANNEL_LOGOUT_EVENT, Map.of()))
                .claim("sid", sid);

        JwtClaimsSet claims = claimsBuilder.build();
        // TODO: 실제 사용하는 서명 키에 맞는 알고리즘으로 변경 필요 (예: application.yml 에서 설정값 읽기)
        JwsHeader headers = JwsHeader.with(SignatureAlgorithm.RS256).build();

        logger.debug("[백채널 토큰 생성] 클라이언트 [{}] 로그아웃 토큰 인코딩. Claims: {}", clientId, claims.getClaims());
        JwtEncoderParameters parameters = JwtEncoderParameters.from(headers, claims);
        return this.jwtEncoder.encode(parameters).getTokenValue();
    }

    /**
     * 지정된 URI로 Back-Channel Logout 요청(POST) 전송
     *
     * @param targetClientId 대상 클라이언트 ID (로깅용)
     * @param uri 대상 RP의 Back-Channel Logout Endpoint URI
     * @param logoutToken 전송할 Logout Token
     */
    private void sendBackChannelLogoutRequest(String targetClientId, String uri, String logoutToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("logout_token", logoutToken);
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);

        try {
            logger.info("[백채널 요청] 클라이언트 [{}] ({})에게 Back-Channel 로그아웃 요청 전송 시도...", targetClientId, uri);
            ResponseEntity<String> response = restTemplate.postForEntity(uri, requestEntity, String.class);
            logger.info("[백채널 요청] 클라이언트 [{}] 요청 결과: {}", targetClientId, response.getStatusCode());
        } catch (Exception e) {
            logger.error("[백채널 요청 실패] 클라이언트 [{}] ({}) 요청 중 오류 발생: {}", targetClientId, uri, e.getMessage());
        }
    }

    /**
     * 활성 상태이고 Back-Channel Logout URI가 설정된 모든 TnClient 엔티티를 조회합니다.
     *
     * @return 조건에 맞는 TnClient 목록
     */
    private Iterable<TnClient> findActiveClientsWithBackChannelLogoutUri() {
        logger.debug("[백채널 대상 조회] 활성 상태이고 Back-Channel URI가 설정된 클라이언트 조회 시작...");
        try {
            List<TnClient> activeClients = tnClientRepository.findActiveClientsWithBackchannelUri();

            List<TnClient> targetClients = activeClients.stream()
                    .filter(client -> "1".equals(client.getClientStatus())) // 활성 상태 필터링
                    .filter(client -> Optional.ofNullable(client.getTmClientSetting()) // 설정 객체 null 체크
                            .map(TmClientSetting::getBackchannelLogoutUri) // URI 추출
                            .filter(StringUtils::hasText) // 비어있지 않은지 확인
                            .isPresent()) // 조건 만족 여부 확인
                    .toList(); // Java 16+

            logger.debug("[백채널 대상 조회] 조회 조건에 맞는 클라이언트 {}개 발견", targetClients.size());
            return targetClients;

        } catch (Exception e) {
            logger.error("[백채널 대상 조회 실패] DB 조회 중 오류 발생", e);
            return Collections.emptyList(); // 오류 발생 시 빈 목록 반환
        }
    }
}
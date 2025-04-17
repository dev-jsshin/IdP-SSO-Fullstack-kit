package com.idpserver.global.security.repository;

import com.idpserver.global.common.response.code.StatusCode;
import com.idpserver.global.common.response.exception.GeneralException;
import com.idpserver.global.common.utils.IpUtils;
import com.idpserver.global.entity.client.TnClient;
import com.idpserver.global.security.service.RegisteredClientService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.*;

@Component
@RequiredArgsConstructor
public class CustomRegisteredClientRepository implements RegisteredClientRepository {

    private static final Logger log = LoggerFactory.getLogger(CustomRegisteredClientRepository.class);

    private static final String CLIENT_STATUS_ACTIVE = "1";

    @Autowired
    private TnClientRepository clientRepository;

    @Autowired
    private RegisteredClientService registeredClientService;

    /**
     * CLIENT_SN(PK)을 기반으로 RegisteredClient를 찾기.
     *
     * @param identifier CLIENT_SN
     * @return 조회된 RegisteredClient 객체
     * @throws GeneralException 클라이언트를 찾을 수 없거나 유효하지 않은 경우
     */
    @Override
    public RegisteredClient findById(String identifier) {

        String clientIp = IpUtils.getClientIpAddress();
        log.info("------ 클라이언트 DB 조회 CLIENT_SN: [{}] IP: [{}]", identifier, clientIp);

        if (!StringUtils.hasText(identifier)) {
            throw createConfigurationError("client_id를 찾을 수 없습니다.");
        }

        Optional<TnClient> clientOptional = clientRepository.findByClientSn(Long.valueOf(identifier));
        if (clientOptional.isEmpty()) {
            throw new GeneralException(StatusCode.BAD_REQUEST, "client_id를 찾을 수 없습니다.");
        }

        TnClient tnClient = clientOptional.get();

        return validateAndBuildRegisteredClient(tnClient, clientIp);
    }

    /**
     * CLIENT_ID를 기반으로 RegisteredClient를 찾기.
     *
     * @param clientId CLIENT_ID
     * @return 조회된 RegisteredClient 객체
     * @throws GeneralException 클라이언트를 찾을 수 없거나 유효하지 않은 경우
     */
    @Override
    public RegisteredClient findByClientId(String clientId) {

        String clientIp = IpUtils.getClientIpAddress();
        log.info("------ 클라이언트 DB 조회 CLIENT_ID: [{}] IP: [{}]", clientId, clientIp);

        if (!StringUtils.hasText(clientId)) {
            throw createConfigurationError("client_id를 찾을 수 없습니다.");
        }

        Optional<TnClient> clientOptional = clientRepository.findByClientId(clientId);
        if (clientOptional.isEmpty()) {
            throw createConfigurationError("client_id를 찾을 수 없습니다.");
        }

        TnClient tnClient = clientOptional.get();

        return validateAndBuildRegisteredClient(tnClient, clientIp);
    }


    /**
     * 조회된 TnClient 객체의 유효성을 검사하고 RegisteredClientService를 통해 변환
     *
     * @param tnClient   DB에서 조회된 TnClient 객체
     * @param clientIp   요청 IP 주소 (로그용)
     * @return 생성된 RegisteredClient 객체
     * @throws OAuth2AuthenticationException 클라이언트가 유효하지 않거나 설정 오류 발생 시
     */
    private RegisteredClient validateAndBuildRegisteredClient(TnClient tnClient, String clientIp) {

        log.info("RegisteredClient 변환 대상 CLIENT_SN: [{}] CLIENT_ID: [{}] IP: [{}]",
                                                        tnClient.getClientSn(),
                                                        tnClient.getClientId(),
                                                        clientIp);

        // 클라이언트 상태 확인 ('1' 정상 상태만 유효)
        if (!CLIENT_STATUS_ACTIVE.equals(tnClient.getClientStatus())) {
            log.info("클라이언트의 상태가 정상이 아닙니다. CLIENT_ID: [{}] STATUS: [{}]", tnClient.getClientId(), tnClient.getClientStatus());
            throw createConfigurationError("client_id를 찾을 수 없습니다.");
        }

        try {
            RegisteredClient registeredClient = registeredClientService.buildRegisteredClient(tnClient);
            log.info("RegisteredClient 객체 생성 완료. CLIENT_ID: [{}]", registeredClient.toString());
            return registeredClient;
        } catch (OAuth2AuthenticationException e) {
            log.warn("RegisteredClient 객체 생성 중 클라이언트 설정 오류 발생. CLIENT_ID: [{}]", tnClient.getClientId(), e);
            throw e;
        } catch (Exception e) {
            log.error("RegisteredClient 객체 생성 중 예상치 못한 오류 발생. CLIENT_ID: [{}]", tnClient.getClientId(), e);

            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                            "클라이언트 정보를 처리하는 중 서버 오류가 발생했습니다. 관리자에게 문의 바랍니다.", null), e); // 원인 예외 포함
        }

    }

    /**
     * 클라이언트 설정 오류 발생 시 OAuth2AuthenticationException을 생성하는 헬퍼 메서드.
     * @param message 사용자에게 전달될 수 있는 오류 설명
     * @return 생성된 OAuth2AuthenticationException 객체
     */
    private OAuth2AuthenticationException createConfigurationError(String message) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, message, null));
    }

    @Override
    public void save(RegisteredClient registeredClient) {}
}
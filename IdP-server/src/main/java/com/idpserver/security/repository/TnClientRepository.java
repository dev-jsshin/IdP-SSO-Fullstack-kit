package com.idpserver.security.repository;

import com.idpserver.entity.client.TnClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TnClientRepository extends JpaRepository<TnClient, Long> {

    Optional<TnClient> findByClientId(String clientId);

    Optional<TnClient> findByClientSn(Long clientSn);

    @Query("SELECT tc FROM TnClient tc JOIN FETCH tc.tmClientSetting tcs WHERE tc.clientStatus = '1' AND tcs.backchannelLogoutSessionRequired = 'Y' AND tcs.backchannelLogoutUri IS NOT NULL AND tcs.backchannelLogoutUri <> ''")
    List<TnClient> findActiveClientsWithBackchannelUri();
}
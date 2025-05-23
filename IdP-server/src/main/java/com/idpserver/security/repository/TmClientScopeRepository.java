package com.idpserver.security.repository;

import com.idpserver.entity.client.TmClientScope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TmClientScopeRepository extends JpaRepository<TmClientScope, Long> {

    List<TmClientScope> findByClientSn(Long clientSn);
}

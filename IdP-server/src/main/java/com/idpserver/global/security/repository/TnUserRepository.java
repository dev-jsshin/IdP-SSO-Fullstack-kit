package com.idpserver.global.security.repository;

import com.idpserver.global.entity.user.TnUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TnUserRepository extends JpaRepository<TnUser, Integer> {

    Optional<TnUser> findByUserId(String userId);
}

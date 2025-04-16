package com.idpserver.global.security.service;

import com.idpserver.global.entity.user.TnUser;
import com.idpserver.global.security.entity.CustomUserDetails;
import com.idpserver.global.security.repository.TnUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private TnUserRepository tnUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {


        TnUser tnUser = tnUserRepository.findByUserId(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자 계정 또는 비밀번호를 다시 확인하세요."));

        return new CustomUserDetails(tnUser);
    }
}


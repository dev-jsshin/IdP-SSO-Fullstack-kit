package com.idpserver.security.entity;

import com.idpserver.entity.user.TnUser;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Builder
@NoArgsConstructor
@Getter
@Setter
public class CustomUserDetails implements UserDetails {

    private TnUser tnUser;

    public CustomUserDetails(TnUser tnUser){
        this.tnUser = tnUser;
    }

    @Override
    public String getUsername() {
        return tnUser.getUserId();
    }

    @Override
    public String getPassword() {
        return tnUser.getPassword();
    }


    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(tnUser.getUserType()));
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    public boolean isEnabled() {
        return true;
    }
}

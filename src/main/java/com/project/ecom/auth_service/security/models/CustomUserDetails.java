package com.project.ecom.auth_service.security.models;

import com.project.ecom.auth_service.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class CustomUserDetails implements UserDetails {
    private User user;

    public CustomUserDetails(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // what we call a user's Role, spring security is calling it a GrantedAuthority
        return user.getRoles().stream().map(CustomGrantedAuthority::new).toList();
    }

    @Override
    public String getPassword() {
        return user.getPassword();  // ** note: user password is stored in encoded form
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;  // user account never expires
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;  // user account cannot be locked
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;  // password never expires
    }

    @Override
    public boolean isEnabled() {
        return true;  // user is always active
    }
}

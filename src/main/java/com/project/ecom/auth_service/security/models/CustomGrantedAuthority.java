package com.project.ecom.auth_service.security.models;

import com.project.ecom.auth_service.models.Role;
import org.springframework.security.core.GrantedAuthority;

public class CustomGrantedAuthority implements GrantedAuthority {
    private Role role;

    public CustomGrantedAuthority(Role role) {
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return role.getName();
    }
}

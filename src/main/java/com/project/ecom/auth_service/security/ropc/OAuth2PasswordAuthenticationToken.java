package com.project.ecom.auth_service.security.ropc;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Set;

@Getter
public class OAuth2PasswordAuthenticationToken extends AbstractAuthenticationToken {
    private final String username;
    private final String password;
    private final Set<String> scopes;
    @Setter
    private Authentication authentication;

    public OAuth2PasswordAuthenticationToken(String username, String password, Set<String> scopes) {
        super(null);
        this.username = username;
        this.password = password;
        this.scopes = scopes;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return this.password;
    }

    @Override
    public Object getPrincipal() {
        return this.authentication.getPrincipal();
    }
}

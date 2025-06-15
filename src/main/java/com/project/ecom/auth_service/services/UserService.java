package com.project.ecom.auth_service.services;

import com.project.ecom.auth_service.dtos.AccessTokenResponse;
import com.project.ecom.auth_service.strategies.OAuth2TokenGenerationStrategy;
import com.project.ecom.auth_service.strategies.TokenGenerationStrategy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class UserService implements IUserService {
    private final AuthenticationManager authenticationManager;
    private final TokenGenerationStrategy tokenGenerationStrategy;

    @Autowired
    public UserService(AuthenticationManager authenticationManager, @Qualifier("OAuth2TokenGenerationStrategy") TokenGenerationStrategy tokenGenerationStrategy) {
        this.authenticationManager = authenticationManager;
        this.tokenGenerationStrategy = tokenGenerationStrategy;
    }

    @Override
    public AccessTokenResponse login(String email, String password) {
        // will throw an exception like BadCredentialsException if the authentication fails
        Authentication authentication = this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );

        return this.tokenGenerationStrategy.generateToken(authentication);
    }
}

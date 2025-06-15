package com.project.ecom.auth_service.security.ropc;

import com.project.ecom.auth_service.strategies.OAuth2TokenGenerationStrategy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {
    private final AuthenticationManager authenticationManager;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final OAuth2TokenGenerationStrategy oAuth2TokenGenerationStrategy;

    public OAuth2PasswordAuthenticationProvider(AuthenticationManager authenticationManager,
                                                OAuth2AuthorizationService authorizationService,
                                                OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, OAuth2TokenGenerationStrategy oAuth2TokenGenerationStrategy) {
        this.authenticationManager = authenticationManager;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.oAuth2TokenGenerationStrategy = oAuth2TokenGenerationStrategy;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2PasswordAuthenticationToken authRequest = (OAuth2PasswordAuthenticationToken) authentication;

        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken(
                authRequest.getUsername(), authRequest.getPassword());

        Authentication authenticatedUser = authenticationManager.authenticate(userAuth);
        if (!authenticatedUser.isAuthenticated()) {
            throw new BadCredentialsException("Invalid credentials");
        }
        // Save full authenticated user inside the custom token
        authRequest.setAuthentication(authenticatedUser);
        // Build token context and generate access token
        RegisteredClient registeredClient = oAuth2TokenGenerationStrategy.getDefaultRegisteredClient();
        Jwt jwt = oAuth2TokenGenerationStrategy.generateJwt(authenticatedUser, registeredClient);
        OAuth2AccessToken accessToken = oAuth2TokenGenerationStrategy.generateAccessToken(jwt);
        // Save the generated token
        OAuth2Authorization authorization = oAuth2TokenGenerationStrategy.getAuthorization(authenticatedUser, registeredClient, jwt, accessToken);
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            refreshToken = oAuth2TokenGenerationStrategy.generateRefreshToken(authenticatedUser, registeredClient, authorization, accessToken);
            authorization = oAuth2TokenGenerationStrategy.getAuthorizationWithRefreshToken(authorization, refreshToken);
        }
        this.authorizationService.save(authorization);
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authenticatedUser, accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

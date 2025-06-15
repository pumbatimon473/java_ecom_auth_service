package com.project.ecom.auth_service.strategies;

import com.project.ecom.auth_service.dtos.AccessTokenResponse;
import com.project.ecom.auth_service.security.configurations.RegisteredClientLoader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class OAuth2TokenGenerationStrategy implements TokenGenerationStrategy {
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final OAuth2TokenGenerator<?> tokenGenerator;
    @Value("${spring.application.name}")
    private String iss;

    public OAuth2TokenGenerationStrategy(RegisteredClientRepository registeredClientRepository, OAuth2TokenGenerator<?> tokenGenerator, OAuth2AuthorizationService oAuth2AuthorizationService) {
        this.registeredClientRepository = registeredClientRepository;
        this.tokenGenerator = tokenGenerator;
        this.oAuth2AuthorizationService = oAuth2AuthorizationService;
    }

    @Override
    public AccessTokenResponse generateToken(Authentication authentication) {
        AccessTokenResponse.AccessTokenResponseBuilder accessTokenResponseBuilder = AccessTokenResponse.builder();
        // step 1: generate the token
        RegisteredClient registeredClient = getDefaultRegisteredClient();
        Jwt jwt = generateJwt(authentication, registeredClient);

        // step 2: persist the token manually
        // step 2.1: Spring Authorization Server expects a token object like OAuth2AccessToken, not a raw Jwt
        OAuth2AccessToken accessToken = generateAccessToken(jwt);
        OAuth2Authorization authorization = getAuthorization(authentication, registeredClient, jwt, accessToken);
        // step 2.2: Generate RefreshToken
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2RefreshToken refreshToken = generateRefreshToken(authentication, registeredClient, authorization, accessToken);
            authorization = getAuthorizationWithRefreshToken(authorization, refreshToken);
            accessTokenResponseBuilder.refreshToken(refreshToken.getTokenValue());
        }
        oAuth2AuthorizationService.save(authorization);

        /*
        OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                .expiresIn(Duration.between(Instant.now(), accessToken.getExpiresAt()).getSeconds())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes())
                .build();
        */

        return accessTokenResponseBuilder
                .accessToken(jwt.getTokenValue())
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(Duration.between(Instant.now(), jwt.getExpiresAt()).getSeconds())
                .build();
    }

    public RegisteredClient getDefaultRegisteredClient() {
        return this.registeredClientRepository.findByClientId(RegisteredClientLoader.ECOM_CLIENT);
    }

    public Jwt generateJwt(Authentication authentication, RegisteredClient registeredClient) {
        DefaultOAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                //.authorizationServerContext(AuthorizationServerContextHolder.getContext())  // null because the flow does not go through /oauth2/token. Here, we are trying to generate the token manually
                .authorizationServerContext(new AuthorizationServerContext() {
                    @Override
                    public String getIssuer() {
                        return iss;
                    }

                    @Override
                    public AuthorizationServerSettings getAuthorizationServerSettings() {
                        return AuthorizationServerSettings.builder()
                                .issuer("http://localhost:8090")
                                .build();
                    }
                })
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrant(authentication)
                .authorizedScopes(registeredClient.getScopes())
                .build();

        return (Jwt) this.tokenGenerator.generate(tokenContext);
    }

    public OAuth2AccessToken generateAccessToken(Jwt jwt) {
        List<String> scopesList = jwt.getClaimAsStringList("scope");
        Set<String> scopes = scopesList != null ? new HashSet<>(scopesList) : Set.of();
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(),
                jwt.getIssuedAt(),
                jwt.getExpiresAt(),
                scopes
        );
    }

    public OAuth2Authorization getAuthorization(Authentication authentication, RegisteredClient registeredClient, Jwt jwt, OAuth2AccessToken accessToken) {
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(authentication.getName())
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(accessToken.getScopes())
                .token(accessToken, metadata -> {
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims());
                })
                .build();
    }

    public OAuth2Authorization getAuthorizationWithRefreshToken(OAuth2Authorization oAuth2Authorization, OAuth2RefreshToken refreshToken) {
        return OAuth2Authorization.from(oAuth2Authorization).refreshToken(refreshToken).build();
    }

    public OAuth2RefreshToken generateRefreshToken(Authentication authentication, RegisteredClient registeredClient, OAuth2Authorization oAuth2Authorization, OAuth2AccessToken accessToken) {
        DefaultOAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorization(oAuth2Authorization)
                .authorizedScopes(accessToken.getScopes())  // Optional
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrant(authentication)
                .build();

        return (OAuth2RefreshToken) this.tokenGenerator.generate(tokenContext);
    }
}

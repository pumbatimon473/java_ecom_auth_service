package com.project.ecom.auth_service.security.configurations;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class RegisteredClientLoader {
    public static final String ECOM_CLIENT = "ecom-app";
    public static final String POSTMAN_CLIENT = "postman";

    @Bean
    public CommandLineRunner registerEcomClient(PasswordEncoder passwordEncoder, RegisteredClientRepository registeredClientRepository) {
        return args -> {
            if (registeredClientRepository.findByClientId(ECOM_CLIENT) == null) {
                RegisteredClient ecomClient = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(ECOM_CLIENT)
                        .clientSecret(passwordEncoder.encode("secret"))  // {noop} stands for "No Operation" for password encoding
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)  // Generates JWT
                                .accessTokenTimeToLive(Duration.ofMinutes(10))
                                .build())
                        .build();

                registeredClientRepository.save(ecomClient);
            }
        };
    }

    @Bean
    public CommandLineRunner registerPostmanClient(PasswordEncoder passwordEncoder, RegisteredClientRepository registeredClientRepository) {
        return args -> {
            if (registeredClientRepository.findByClientId(POSTMAN_CLIENT) == null) {
                RegisteredClient postmanClient = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(POSTMAN_CLIENT)
                        .clientSecret(passwordEncoder.encode("secret"))  // {noop} stands for "No Operation" for password encoding
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        // .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")  // Test with Browser
                        .redirectUri("https://oauth.pstmn.io/v1/callback")  // Test with Postman
                        .postLogoutRedirectUri("http://127.0.0.1:8080/")
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                        .build();

                registeredClientRepository.save(postmanClient);
            }
        };
    }
}

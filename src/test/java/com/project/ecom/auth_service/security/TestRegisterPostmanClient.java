package com.project.ecom.auth_service.security;

import com.project.ecom.auth_service.security.repositories.JpaRegisteredClientRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

@SpringBootTest
public class TestRegisterPostmanClient {
    private final String POSTMAN_CLIENT = "postman";
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JpaRegisteredClientRepository registeredClientRepository;

    @Test
    public void testRegisterPostmanClient() {
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
    }
}

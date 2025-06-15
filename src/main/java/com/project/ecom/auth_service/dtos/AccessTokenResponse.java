package com.project.ecom.auth_service.dtos;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

@Getter
@Setter
@Builder
public class AccessTokenResponse {
    private String accessToken;
    private String refreshToken;
    private OAuth2AccessToken.TokenType tokenType;
    private Long expiresIn;  // seconds
}

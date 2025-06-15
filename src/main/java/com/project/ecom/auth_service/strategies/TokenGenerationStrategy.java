package com.project.ecom.auth_service.strategies;

import com.project.ecom.auth_service.dtos.AccessTokenResponse;
import org.springframework.security.core.Authentication;

public interface TokenGenerationStrategy {
    AccessTokenResponse generateToken(Authentication authentication);
}

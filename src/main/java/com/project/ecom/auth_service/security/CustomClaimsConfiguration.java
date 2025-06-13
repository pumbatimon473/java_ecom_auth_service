package com.project.ecom.auth_service.security;

import com.project.ecom.auth_service.security.models.CustomUserDetails;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/* Reference Doc: How-to: Add authorities as custom claims in JWT access tokens
https://docs.spring.io/spring-authorization-server/reference/guides/how-to-custom-claims-authorities.html
 */

@Configuration
public class CustomClaimsConfiguration {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claims((claims) -> {
                    Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
                            .stream()
                            // .map(c -> c.replaceFirst("^ROLE_", ""))
                            .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
                    claims.put("authorities", roles);  // spring expects the claim for "roles" to be "authorities"
                    CustomUserDetails userDetails = (CustomUserDetails) context.getPrincipal().getPrincipal();
                    claims.put("user_id", userDetails.getUserId());
                });
            }
        };
    }
}

package com.project.ecom.auth_service.strategies;

import com.project.ecom.auth_service.dtos.AccessTokenResponse;
import com.project.ecom.auth_service.exceptions.UserNotFoundException;
import com.project.ecom.auth_service.models.Session;
import com.project.ecom.auth_service.models.SessionStatus;
import com.project.ecom.auth_service.repositories.ISessionRepository;
import com.project.ecom.auth_service.repositories.IUserRepository;
import com.project.ecom.auth_service.security.models.CustomUserDetails;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Date;

@Component
public class JJWTGenerationStrategy implements TokenGenerationStrategy {
    private static final String SECRET = System.getenv("JWT_SECRET");
    private final ISessionRepository sessionRepo;
    private final IUserRepository userRepo;
    @Value("${spring.application.name}")
    private String iss;

    @Autowired
    public JJWTGenerationStrategy(ISessionRepository sessionRepo, IUserRepository userRepo) {
        this.sessionRepo = sessionRepo;
        this.userRepo = userRepo;
    }

    @Override
    public AccessTokenResponse generateToken(Authentication authentication) {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        Long userId = userDetails.getUserId();

        Calendar calendar = Calendar.getInstance();
        Date iat = calendar.getTime();
        calendar.add(Calendar.MINUTE, 10);
        Date exp = calendar.getTime();

        String jwt = Jwts.builder()
                .subject(userDetails.getUsername())
                .issuer(iss)
                .issuedAt(iat)
                .expiration(exp)
                .signWith(SignatureAlgorithm.HS256, JJWTGenerationStrategy.SECRET.getBytes(StandardCharsets.UTF_8))
                .compact();

        // store the jwt in the session
        Session session = new Session();
        session.setUser(this.userRepo.findById(userId).orElseThrow(() -> new UserNotFoundException(userId)));
        session.setToken(jwt);
        session.setExpiryDate(exp);
        session.setStatus(SessionStatus.ACTIVE);
        this.sessionRepo.save(session);

        return AccessTokenResponse.builder()
                .accessToken(jwt)
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(exp.toInstant().getEpochSecond())
                .build();
    }
}

package com.project.ecom.auth_service.utils;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Map;

public class JwtUtil {
    private static final String SECRET = System.getenv("JWT_SECRET");

    public static Map<String, Object> getClaims(String accessToken) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        return jwtClaimsSet.getClaims();
    }

    public static Boolean verifySignature(String accessToken) {
        try {
            JwtUtil.getJwtDecoder().decode(accessToken);
        } catch (JwtException e) {
            return Boolean.FALSE;
        }
        return Boolean.TRUE;
    }

    // Singleton Pattern for JwtDecoder: static inner class
    private static final class JwtDecoderHolder {
        private static final JwtDecoder jwtDecoder = NimbusJwtDecoder
                .withSecretKey(Keys.hmacShaKeyFor(JwtUtil.SECRET.getBytes(StandardCharsets.UTF_8)))
                .build();
    }

    private static JwtDecoder getJwtDecoder() {
        return JwtDecoderHolder.jwtDecoder;
    }
}

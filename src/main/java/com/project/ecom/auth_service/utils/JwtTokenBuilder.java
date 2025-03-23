package com.project.ecom.auth_service.utils;

import com.project.ecom.auth_service.models.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Date;

public class JwtTokenBuilder {
    private static final String SECRET = System.getenv("JWT_SECRET");

    public static String from(User user) {
        if (JwtTokenBuilder.SECRET == null || JwtTokenBuilder.SECRET.isEmpty())
            throw new IllegalStateException("Environment variable JWT_SECRET is not set");

        Calendar calendar = Calendar.getInstance();
        Date iat = calendar.getTime();
        calendar.add(Calendar.HOUR, 1);
        Date exp = calendar.getTime();

        return Jwts.builder()
                .subject(user.getId().toString())
                .issuer("ecom_auth_service")
                .issuedAt(iat)
                .expiration(exp)
                .claim("email", user.getEmail())
                .signWith(SignatureAlgorithm.HS256, JwtTokenBuilder.SECRET.getBytes(StandardCharsets.UTF_8))
                .compact();
    }
}

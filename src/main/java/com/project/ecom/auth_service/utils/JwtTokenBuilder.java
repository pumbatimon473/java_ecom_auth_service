package com.project.ecom.auth_service.utils;

import com.project.ecom.auth_service.models.User;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Date;

/* Standard Jwt Claim Reference:
https://www.iana.org/assignments/jwt/jwt.xhtml
 */

public class JwtTokenBuilder {
    private static final String SECRET = System.getenv("JWT_SECRET");
    @Value("${spring.application.name}")
    private static String iss;
    // private static final SignatureAlgorithm SIGN_ALGO = SignatureAlgorithm.HS256;

    private static void verifySecret() {
        if (JwtTokenBuilder.SECRET == null || JwtTokenBuilder.SECRET.isEmpty())
            throw new IllegalStateException("Environment variable JWT_SECRET is not set");
    }

    public static String from(User user) {
        JwtTokenBuilder.verifySecret();

        Calendar calendar = Calendar.getInstance();
        Date iat = calendar.getTime();
        calendar.add(Calendar.HOUR, 1);
        Date exp = calendar.getTime();

        JwtBuilder jwtBuilder = Jwts.builder()
                .subject(user.getEmail())
                .issuer(iss)
                .issuedAt(iat)
                .expiration(exp)
                .claim("user_id", user.getId());

        JwtTokenBuilder.signWith(jwtBuilder);
        return jwtBuilder.compact();
    }

    public static String generatePasswordResetToken(User user) {
        JwtTokenBuilder.verifySecret();

        Calendar now = Calendar.getInstance();
        Date iat = now.getTime();
        now.add(Calendar.MINUTE, 10);
        Date exp = now.getTime();

        JwtBuilder jwtBuilder = Jwts.builder()
                .subject(user.getEmail())
                .issuedAt(iat)
                .expiration(exp)
                .claim("user_id", user.getId())
                .claim("purpose", "reset_password")
                .issuer(iss);

        JwtTokenBuilder.signWith(jwtBuilder);
        return jwtBuilder.compact();
    }

    private static void signWith(JwtBuilder jwtBuilder) {
        SecretKey secretKey = Keys.hmacShaKeyFor(JwtTokenBuilder.SECRET.getBytes(StandardCharsets.UTF_8));
        jwtBuilder.signWith(secretKey);
    }
}

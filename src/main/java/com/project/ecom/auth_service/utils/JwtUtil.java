package com.project.ecom.auth_service.utils;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.Map;

public class JwtUtil {
    private static final String SECRET = System.getenv("JWT_SECRET");

    public static Map<String, Object> getClaims(String accessToken) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        return jwtClaimsSet.getClaims();
    }
}

package com.antivirus.server.security;

import com.antivirus.server.models.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Service
public class JwtService {

    private final SecretKey key;
    private final long accessExpMs;
    private final long refreshExpMs;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms}") long accessExpMs,
            @Value("${jwt.refresh-expiration-ms}") long refreshExpMs
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExpMs = accessExpMs;
        this.refreshExpMs = refreshExpMs;
    }



    public String generateAccessToken(User user) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + accessExpMs))
                .addClaims(Map.of(
                        "token_type", "access"
                ))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(User user, String deviceId) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setId(UUID.randomUUID().toString())         // jti
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + refreshExpMs))
                .addClaims(deviceId == null || deviceId.isBlank()
                        ? Map.of("token_type", "refresh")
                        : Map.of("token_type", "refresh", "deviceId", deviceId))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }



    public Claims parse(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody();
    }

    public String extractUsername(String token) {
        return parse(token).getSubject();
    }

    public Date getExpiration(String token) {
        return parse(token).getExpiration();
    }

    public String getTokenType(String token) {
        Object v = parse(token).get("token_type");
        return v == null ? null : v.toString();
    }

    public String getDeviceId(String token) {
        Object v = parse(token).get("deviceId");
        return v == null ? null : v.toString();
    }

    public boolean isAccessToken(String token) {
        return "access".equals(getTokenType(token));
    }

    public boolean isRefreshToken(String token) {
        return "refresh".equals(getTokenType(token));
    }
}

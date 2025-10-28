package com.antivirus.server.services;

import com.antivirus.server.models.RefreshToken;
import com.antivirus.server.models.User;
import com.antivirus.server.repository.RefreshTokenRepository;
import com.antivirus.server.security.JwtService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repo;
    private final JwtService jwt;

    public RefreshTokenService(RefreshTokenRepository repo, JwtService jwt) {
        this.repo = repo;
        this.jwt = jwt;
    }


    public RefreshToken issueJwt(User user, String deviceId) {
        String raw = jwt.generateRefreshToken(user, deviceId);
        Instant exp = jwt.getExpiration(raw).toInstant();

        RefreshToken t = new RefreshToken();
        t.setUser(user);
        t.setExpiryDate(exp);
        t.setTokenHash(sha256(raw));
        t.setRevoked(false);
        repo.save(t);

        t.setToken(raw);
        return t;
    }

    public Optional<RefreshToken> findActiveByRaw(String raw) {
        return repo.findByTokenHash(sha256(raw))
                .filter(t -> !t.getRevoked() && t.getExpiryDate().isAfter(Instant.now()));
    }

    @Transactional
    public RefreshToken rotate(RefreshToken oldToken, User user, String deviceId) {
        oldToken.setRevoked(true);
        repo.save(oldToken);
        return issueJwt(user, deviceId);
    }

    public void deleteByUserId(UUID userId) {
        repo.deleteByUser_Id(userId);
    }

    private static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

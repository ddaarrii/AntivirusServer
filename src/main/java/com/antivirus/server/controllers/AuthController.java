package com.antivirus.server.controllers;

import com.antivirus.server.dto.LoginRequest;
import com.antivirus.server.dto.RefreshRequest;
import com.antivirus.server.dto.RegisterRequest;
import com.antivirus.server.models.RefreshToken;
import com.antivirus.server.models.User;
import com.antivirus.server.repository.UserRepository;
import com.antivirus.server.security.JwtService;
import com.antivirus.server.services.RefreshTokenService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final RefreshTokenService refresh;

    public AuthController(UserRepository users, PasswordEncoder encoder,
                          JwtService jwt, RefreshTokenService refresh) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
        this.refresh = refresh;
    }

    @PostMapping("/registration")
    public ResponseEntity<?> registration(@RequestBody RegisterRequest req) {
        if (req.login == null || req.password == null) return ResponseEntity.badRequest().build();
        if (users.existsByUsername(req.login)) return ResponseEntity.badRequest().body("Пользователь уже существует");
        User u = new User();
        u.setUsername(req.login);
        u.setPassword(encoder.encode(req.password));
        users.save(u);
        return ResponseEntity.ok("Пользователь зарегистрирован");
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        var user = users.findByUsername(req.login).orElse(null);
        if (user == null || !encoder.matches(req.password, user.getPassword()))
            return ResponseEntity.status(401).body("Неверный логин или пароль");

        // NEW: делаем JWT-access и JWT-refresh
        String access = jwt.generateAccessToken(user);
        RefreshToken rt = refresh.issueJwt(user, req.deviceId); // сохраняет hash, возвращает RAW JWT в t.token
        return ResponseEntity.ok(new AuthResponse(access, rt.getToken()));
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest req) {
        // Ищем по hash
        var tokenOpt = refresh.findActiveByRaw(req.refreshToken);
        if (tokenOpt.isEmpty()) return ResponseEntity.status(403).body("Refresh token не найден или истёк");

        // Доп.проверки: этот JWT действительно refresh и принадлежит тому же юзеру
        if (!jwt.isRefreshToken(req.refreshToken)) {
            return ResponseEntity.status(403).body("Неверный тип токена");
        }

        var old = tokenOpt.get();
        var user = old.getUser();

        // subject в JWT должен совпадать с username владельца
        String sub = jwt.extractUsername(req.refreshToken);
        if (!user.getUsername().equals(sub)) {
            return ResponseEntity.status(403).body("Токен не принадлежит пользователю");
        }

        String deviceId = jwt.getDeviceId(req.refreshToken); // может быть null
        String newAccess = jwt.generateAccessToken(user);
        RefreshToken newRefresh = refresh.rotate(old, user, deviceId);

        return ResponseEntity.ok(new AuthResponse(newAccess, newRefresh.getToken()));
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<?> logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String auth) {
        if (auth != null && auth.startsWith("Bearer ")) {
            var username = jwt.extractUsername(auth.substring(7));
            users.findByUsername(username).ifPresent(u -> refresh.deleteByUserId(u.getId()));
        }
        return ResponseEntity.noContent().build();
    }

    public static class AuthResponse {
        public String accessToken;
        public String refreshToken;
        public AuthResponse(String a, String r){ this.accessToken=a; this.refreshToken=r; }
    }
}

package com.davidrr.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.time.Instant;
import java.util.Collection;

@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKeyValue;

    @Value("${security.jwt.expiration:900000}")
    private long jwtExpirationMs;

    @Value("${security.jwt.issuer:code-diary}")
    private String issuer;

    private SecretKey secretKey;

    @PostConstruct
    void init() {
        byte[] keyBytes;
        try {
            keyBytes = java.util.Base64.getDecoder().decode(secretKeyValue);
        } catch (IllegalArgumentException ex) {
            keyBytes = java.util.Base64.getUrlDecoder().decode(secretKeyValue);
        }
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(
                userDetails.getUsername(),
                extractRoles(userDetails.getAuthorities())
        );
    }

    public String generateToken(String username, List<String> roles) {
        Instant now = Instant.now();

        return Jwts.builder()
                .setSubject(username)
                .setIssuer(issuer)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(jwtExpirationMs)))
                .claim("roles", roles)
                .signWith(secretKey)
                .compact();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String extractJti(String token) {
        return extractAllClaims(token).getId();
    }

    public List<String> extractRoles(String token) {
        Claims claims = extractAllClaims(token);
        Object rawRoles = claims.get("roles");

        if (rawRoles instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }

        return List.of();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        Claims claims = extractAllClaims(token);

        String username = claims.getSubject();
        String tokenIssuer = claims.getIssuer();
        Date expiration = claims.getExpiration();

        return username.equals(userDetails.getUsername())
                && issuer.equals(tokenIssuer)
                && expiration.after(new Date());
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private List<String> extractRoles(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}
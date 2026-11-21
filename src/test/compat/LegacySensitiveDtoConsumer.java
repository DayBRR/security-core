import com.davidrr.security.auth.dto.*;
import com.davidrr.security.auth.session.model.RefreshSession;
import java.time.Instant;
import java.util.Objects;

/** Compile against 0.4.0; run against candidate classes, with no test framework. */
public class LegacySensitiveDtoConsumer {
    public static void main(String[] args) {
        AuthRequest request = new AuthRequest();
        request.setUsername("synthetic-user");
        request.setPassword("synthetic-password");
        check("synthetic-user", request.getUsername());
        check("synthetic-password", request.getPassword());
        check(request, new AuthRequest("synthetic-user", "synthetic-password"));
        RegisterRequest registration = new RegisterRequest();
        registration.setUsername("synthetic-user");
        registration.setEmail("synthetic@example.invalid");
        registration.setPassword("synthetic-password");
        check("synthetic-user", registration.getUsername());
        check("synthetic@example.invalid", registration.getEmail());
        check("synthetic-password", registration.getPassword());
        AuthResponse response = new AuthResponse("synthetic-access");
        check("synthetic-access", response.getToken());
        AuthTokens tokens = new AuthTokens("synthetic-access", "synthetic-refresh");
        check("synthetic-access", tokens.accessToken());
        check("synthetic-refresh", tokens.refreshToken());
        RefreshRotationResult rotation = new RefreshRotationResult("synthetic-user", "synthetic-refresh");
        check("synthetic-user", rotation.username());
        check("synthetic-refresh", rotation.refreshToken());
        Instant time = Instant.parse("2026-01-01T00:00:00Z");
        RefreshSession.RefreshSessionBuilder builder = RefreshSession.builder()
                .id(9023L).username("synthetic-user").tokenHash("synthetic-hash-current")
                .createdAt(time).expiresAt(time.plusSeconds(86400)).lastUsedAt(time.plusSeconds(60))
                .revoked(true).revokedAt(time.plusSeconds(120)).revocationReason("synthetic-reason")
                .replacedByTokenHash("synthetic-hash-next").ip("192.0.2.23").userAgent("synthetic-agent");
        RefreshSession session = builder.build();
        check(9023L, session.getId());
        check("synthetic-user", session.getUsername());
        check("synthetic-hash-current", session.getTokenHash());
        check(time, session.getCreatedAt());
        check(time.plusSeconds(86400), session.getExpiresAt());
        check(time.plusSeconds(60), session.getLastUsedAt());
        check(true, session.isRevoked());
        check(time.plusSeconds(120), session.getRevokedAt());
        check("synthetic-reason", session.getRevocationReason());
        check("synthetic-hash-next", session.getReplacedByTokenHash());
        check("192.0.2.23", session.getIp());
        check("synthetic-agent", session.getUserAgent());
        session.setId(9024L);
        session.setUsername("synthetic-user-new");
        session.setTokenHash("synthetic-hash-new");
        session.setCreatedAt(time);
        session.setExpiresAt(time);
        session.setLastUsedAt(time);
        session.setRevoked(false);
        session.setRevokedAt(null);
        session.setRevocationReason(null);
        session.setReplacedByTokenHash(null);
        session.setIp("192.0.2.24");
        session.setUserAgent("synthetic-agent-new");
        check(9024L, session.getId());
        check(false, session.isRevoked());
        Object[] values = {request, registration, response, tokens, rotation, session, builder};
        for (Object value : values) {
            if (!value.toString().endsWith("[REDACTED]")) {
                throw new IllegalStateException("Candidate representation is not redacted");
            }
        }
        System.out.println("Legacy 0.4.0 consumer: PASS (candidate classes, seven types)");
    }

    private static void check(Object expected, Object actual) {
        if (!Objects.equals(expected, actual)) {
            throw new IllegalStateException("Legacy consumer contract mismatch");
        }
    }
}

import com.davidrr.security.audit.*;
import com.davidrr.security.auth.dto.*;
import com.davidrr.security.auth.port.*;
import com.davidrr.security.auth.service.AuthService;
import com.davidrr.security.auth.service.impl.AuthServiceImpl;
import com.davidrr.security.auth.session.model.RefreshSession;
import com.davidrr.security.auth.session.port.RefreshSessionStore;
import com.davidrr.security.auth.session.service.*;
import com.davidrr.security.auth.session.service.impl.*;
import com.davidrr.security.common.*;
import com.davidrr.security.config.SecurityConfig;
import com.davidrr.security.jwt.*;
import com.davidrr.security.ratelimit.config.*;
import com.davidrr.security.ratelimit.service.*;
import com.davidrr.security.ratelimit.util.RateLimitKeyFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.lang.reflect.Method;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/** Compiled ONLY against original 0.4.0; never recompiled against the candidate. */
public class LegacyPublicApiConsumer {
    private static final SessionFingerprint FINGERPRINT = new SessionFingerprint("192.0.2.7", "synthetic-agent");

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("Expected candidate, manifest, public|sensitive");
        Path candidate = Path.of(args[0]).toRealPath();
        int origins = 0;
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            if (!line.contains(" | CLASS modifiers=")) continue;
            Class<?> type = Class.forName(line.substring(0, line.indexOf(" |")), false,
                    LegacyPublicApiConsumer.class.getClassLoader());
            Path origin = Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
            if (!candidate.equals(origin)) throw new AssertionError("Unexpected class origin: " + type.getName());
            origins++;
        }
        if (origins == 0) throw new AssertionError("No class origins checked");
        if (args[2].equals("sensitive")) {
            LegacySensitiveDtoConsumer.main(new String[0]);
        } else if (args[2].equals("public")) {
            publicConsumer();
        } else throw new IllegalArgumentException("Unknown consumer");
        System.out.println("Legacy " + args[2] + " PASS: " + origins + " Security Core class origins verified as candidate");
    }

    private static void publicConsumer() throws Exception {
        LegacyPorts ports = new LegacyPorts();
        // Direct invokeinterface instructions and constructors retain the old JVM descriptors.
        AuthService auth = ports;
        if (!"synthetic-access".equals(auth.login(new AuthRequest("fixture", "synthetic-password"), FINGERPRINT).accessToken()))
            throw new AssertionError("Old AuthService implementation failed");
        UserRegistrationPort registration = ports;
        if (!Long.valueOf(7).equals(registration.register("fixture", "fixture@example.invalid", "encoded").id()))
            throw new AssertionError("Old registration implementation failed");
        // Invoke every candidate interface operation on an implementer compiled against the old API.
        // A newly added abstract operation cannot hide behind a successful constructor/link check.
        for (Class<?> contract : LegacyPorts.class.getInterfaces()) {
            for (Method method : contract.getDeclaredMethods()) {
                if (java.lang.reflect.Modifier.isStatic(method.getModifiers())) continue;
                Object[] arguments = Arrays.stream(method.getParameterTypes()).map(LegacyPublicApiConsumer::argument).toArray();
                method.invoke(ports, arguments);
            }
        }
        JwtService jwt = new JwtService();
        JwtAuthenticationFilter filter = new ProtectedFilter(jwt, ports);
        RestAuthenticationEntryPoint entryPoint = new RestAuthenticationEntryPoint(null);
        RestAccessDeniedHandler denied = new RestAccessDeniedHandler(null);
        new AuthServiceImpl(null, jwt, ports, ports, ports, new RateLimitKeyFactory(), ports, ports, null, null, ports);
        new RefreshTokenServiceImpl(ports, ports, ports);
        new RefreshTokenRevocationServiceImpl(ports);
        new SecurityConfig(filter, entryPoint, denied);
        RateLimitProperties properties = new RateLimitProperties();
        new InMemoryRateLimiterService(properties);
        new RateLimitProperties.Bucket();
        new RateLimitConfig();
        new GlobalExceptionHandler();
        new StructuredLoggingSecurityAuditService();
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        if (!new SessionResponse(7L, now, null, now.plusSeconds(60), "192.0.2.7", "synthetic-agent", "device", true).current())
            throw new AssertionError("SessionResponse linkage failed");
        if (new ApiError(now, 401, "Unauthorized", "FIXTURE", "synthetic", "/fixture").status() != 401)
            throw new AssertionError("ApiError linkage failed");
        SecurityAuditContext context = SecurityAuditContext.minimal("fixture", "192.0.2.7", "synthetic-agent");
        SecurityAuditContext.of(context.username(), context.ip(), context.userAgent(), 7L, "FIXTURE", "synthetic");
        new com.davidrr.security.auth.event.UserRegisteredEvent(7L, "fixture");
    }

    private static Object argument(Class<?> type) {
        if (type == String.class) return "synthetic";
        if (type == Long.class) return 7L;
        if (type == Instant.class) return Instant.parse("2026-01-01T00:00:00Z");
        if (type == List.class) return List.of();
        if (type == AuthRequest.class) return new AuthRequest("fixture", "synthetic-password");
        if (type == RegisterRequest.class) return new RegisterRequest();
        if (type == SessionFingerprint.class) return FINGERPRINT;
        if (type == RefreshSession.class) return RefreshSession.builder().id(7L).username("fixture").build();
        if (type == SecurityAuditContext.class) return SecurityAuditContext.minimal("fixture", null, null);
        if (type == SecurityEventType.class) return SecurityEventType.values()[0];
        throw new AssertionError("Unreviewed interface parameter: " + type.getName());
    }

    private static final class ProtectedFilter extends JwtAuthenticationFilter {
        ProtectedFilter(JwtService jwt, UserProvider users) { super(jwt, users); }
        // Compiling the override also exercises the protected servlet signature and checked exceptions.
        @Override
        protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request,
                jakarta.servlet.http.HttpServletResponse response, jakarta.servlet.FilterChain chain)
                throws jakarta.servlet.ServletException, java.io.IOException {
            super.doFilterInternal(request, response, chain);
        }
    }

    public static final class LegacyPorts implements AuthService, UserProvider, UserRegistrationPort,
            UserLoginAuditPort, RefreshSessionStore, RefreshTokenService, RefreshTokenRevocationService,
            RateLimiterService, SecurityAuditService {
        public AuthTokens register(RegisterRequest request, SessionFingerprint fingerprint) { return tokens(); }
        public AuthTokens login(AuthRequest request, SessionFingerprint fingerprint) { return tokens(); }
        public AuthTokens refresh(String token, SessionFingerprint fingerprint) { return tokens(); }
        public void logout(String token) { }
        public void logoutAll(String token) { }
        public List<SessionResponse> getSessions(String token) { return List.of(); }
        public void revokeSession(String token, Long id) { }
        public UserDetails loadUserByUsername(String name) { return User.withUsername(name).password("encoded").authorities("FIXTURE").build(); }
        public RegisteredUser register(String name, String email, String password) { return new RegisteredUser(7L, name); }
        public void recordSuccessfulLogin(String name) { }
        public RefreshSession save(RefreshSession session) { return session; }
        public List<RefreshSession> saveAll(List<RefreshSession> sessions) { return sessions; }
        public Optional<RefreshSession> findById(Long id) { return Optional.empty(); }
        public Optional<RefreshSession> findByTokenHash(String hash) { return Optional.empty(); }
        public List<RefreshSession> findActiveByUsername(String name) { return List.of(); }
        public List<RefreshSession> findActiveByUsernameOrderByCreatedAtDesc(String name) { return List.of(); }
        public List<RefreshSession> findExpiredActiveSessions(Instant time) { return List.of(); }
        public void deleteById(Long id) { }
        public String createRefreshToken(String name, SessionFingerprint fingerprint) { return "synthetic-refresh"; }
        public String validateAndGetUsername(String token) { return "fixture"; }
        public RefreshRotationResult rotate(String token, SessionFingerprint fingerprint) { return new RefreshRotationResult("fixture", "synthetic-refresh"); }
        public void revoke(String token) { }
        public void revokeAll(String name) { }
        public void cleanupExpired() { }
        public RefreshSession findSessionByToken(String token) { return RefreshSession.builder().id(7L).username("fixture").build(); }
        public List<SessionResponse> getActiveSessions(String token) { return List.of(); }
        public void revokeAllActiveTokens(String name, String reason) { }
        public void check(String bucket, String key) { }
        public void onSuccess(String bucket, String key) { }
        public void onFailure(String bucket, String key) { }
        public void log(SecurityEventType event, SecurityAuditContext context) { }
        private AuthTokens tokens() { return new AuthTokens("synthetic-access", "synthetic-refresh"); }
    }
}

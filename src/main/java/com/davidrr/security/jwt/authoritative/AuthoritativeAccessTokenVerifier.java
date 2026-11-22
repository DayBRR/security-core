package com.davidrr.security.jwt.authoritative;

import com.davidrr.security.account.*;
import java.time.*;
import java.util.Objects;
import static com.davidrr.security.account.SecurityValidationFailure.*;

public final class AuthoritativeAccessTokenVerifier {
    private final JwtCryptographicVerifier jwt;
    private final JwtClaimsCodec codec;
    private final AccountSecurityGate accounts;
    private final Clock clock;
    public AuthoritativeAccessTokenVerifier(JwtCryptographicVerifier jwt, JwtClaimsCodec codec, AccountSecurityGate accounts, Clock clock) {
        this.jwt = Objects.requireNonNull(jwt); this.codec = Objects.requireNonNull(codec);
        this.accounts = Objects.requireNonNull(accounts); this.clock = Objects.requireNonNull(clock);
        if (!jwt.securityContextId().equals(codec.securityContextId()) || !jwt.securityContextId().equals(accounts.securityContextId())) {
            throw new IllegalArgumentException("Mixed security contexts");
        }
    }
    public VerifiedAccessIdentity verify(String compactToken) {
        VerifiedJwtClaims verified = jwt.verify(compactToken);
        TokenAccountClaims claims = codec.decode(verified);
        if (claims == null) throw new SecurityValidationException(CONTRACT_VIOLATION);
        AccountSecuritySnapshot snapshot = accounts.requireForAccess(claims);
        Instant expires = Instant.ofEpochSecond((Long) verified.claims().get("exp"));
        if (!expires.isAfter(clock.instant())) throw new SecurityValidationException(TOKEN_INVALID);
        return new VerifiedAccessIdentity(snapshot, verified.securityContextId(), expires);
    }
}

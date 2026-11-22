package com.davidrr.security.jwt.authoritative;

import com.davidrr.security.account.*;
import java.util.*;
import static com.davidrr.security.account.SecurityValidationFailure.*;

/** Fixed access-v1 identity codec; no legacy name/claim fallback or token issuance. */
public final class StrictIdentityClaimsCodec implements JwtClaimsCodec {
    private final String securityContextId;
    private final Set<String> schemes;
    public StrictIdentityClaimsCodec(String securityContextId, Set<String> acceptedRevisionSchemes) {
        if (securityContextId == null || securityContextId.isBlank() || securityContextId.length() > 128
                || securityContextId.chars().anyMatch(Character::isISOControl)) throw new IllegalArgumentException("Invalid context");
        schemes = Set.copyOf(acceptedRevisionSchemes);
        if (schemes.isEmpty() || !Set.of("counter-v1", "generation-v1").containsAll(schemes)) throw new IllegalArgumentException("Invalid revision schemes");
        this.securityContextId = securityContextId;
    }
    public String securityContextId() { return securityContextId; }

    public TokenAccountClaims decode(VerifiedJwtClaims claims) {
        if (claims == null) throw new SecurityValidationException(TOKEN_INVALID);
        if (!securityContextId.equals(claims.securityContextId())) throw new SecurityValidationException(CONTRACT_VIOLATION);
        try {
            Map<String, Object> values = claims.claims();
            String scheme = text(values.get("security_revision_scheme"));
            String revision = text(values.get("security_revision"));
            if (!schemes.contains(scheme)) throw new IllegalArgumentException();
            if (scheme.equals("counter-v1")) {
                if (!revision.matches("0|[1-9][0-9]{0,18}")) throw new IllegalArgumentException();
                Long.parseLong(revision);
            } else {
                if (!revision.matches("[A-Za-z0-9_-]{43}")) throw new IllegalArgumentException();
                byte[] decoded = Base64.getUrlDecoder().decode(revision);
                if (decoded.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(revision)) throw new IllegalArgumentException();
            }
            return new TokenAccountClaims(new SecurityIdentity(text(values.get("identity_namespace")), text(values.get("sub"))),
                    new SecurityRevision(scheme, revision));
        } catch (IllegalArgumentException failure) { throw new SecurityValidationException(TOKEN_INVALID); }
    }
    private static String text(Object value) {
        if (!(value instanceof String text)) throw new IllegalArgumentException();
        return text;
    }
}

package com.davidrr.security.jwt.authoritative;

import com.davidrr.security.account.TokenAccountClaims;

public interface JwtClaimsCodec {
    String securityContextId();
    TokenAccountClaims decode(VerifiedJwtClaims claims);
}

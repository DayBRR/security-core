package com.davidrr.security.jwt.authoritative;

import java.security.Key;
import java.util.Optional;

/** Local, bounded key lookup within one configured authority; never follows token URLs. */
public interface TrustedJwtKeySource {
    Key verificationKey(Optional<String> keyId, String algorithm);
}

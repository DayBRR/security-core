package com.davidrr.security.spring.account;

import com.davidrr.security.account.AccountSecuritySnapshot;

/** Pure local mapping to a stable, credential-free principal; must not load credentials or state. */
public interface AccessPrincipalMapper {
    MappedAccessPrincipal map(AccountSecuritySnapshot snapshot);
}

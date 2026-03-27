package com.davidrr.security.auth.session.service.impl;

import com.davidrr.security.auth.session.model.RefreshSession;
import com.davidrr.security.auth.session.port.RefreshSessionStore;
import com.davidrr.security.auth.session.service.RefreshTokenRevocationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RefreshTokenRevocationServiceImpl implements RefreshTokenRevocationService {

    private final RefreshSessionStore refreshSessionStore;

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeAllActiveTokens(String username, String reason) {
        Instant now = Instant.now();

        List<RefreshSession> activeSessions = refreshSessionStore.findActiveByUsername(username);

        for (RefreshSession session : activeSessions) {
            session.setRevoked(true);
            session.setRevokedAt(now);
            session.setRevocationReason(reason);

            if (session.getLastUsedAt() == null) {
                session.setLastUsedAt(now);
            }
        }

        refreshSessionStore.saveAll(activeSessions);
    }
}
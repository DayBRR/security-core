package com.davidrr.security.auth.session.port;

import com.davidrr.security.auth.session.model.RefreshSession;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface RefreshSessionStore {

    RefreshSession save(RefreshSession session);

    List<RefreshSession> saveAll(List<RefreshSession> sessions);

    Optional<RefreshSession> findById(Long id);

    Optional<RefreshSession> findByTokenHash(String tokenHash);

    List<RefreshSession> findActiveByUsername(String username);

    List<RefreshSession> findActiveByUsernameOrderByCreatedAtDesc(String username);

    List<RefreshSession> findExpiredActiveSessions(Instant now);

    void deleteById(Long id);
}
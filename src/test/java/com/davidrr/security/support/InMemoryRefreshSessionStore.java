package com.davidrr.security.support;

import com.davidrr.security.auth.session.model.RefreshSession;
import com.davidrr.security.auth.session.port.RefreshSessionStore;

import java.time.Instant;
import java.util.*;
import java.util.function.Predicate;

/** Sequential test double only: no transactions, atomic rotation, durability or multi-node guarantees. */
public final class InMemoryRefreshSessionStore implements RefreshSessionStore {
    private final Map<Long, RefreshSession> sessions = new LinkedHashMap<>();
    private long nextId = 1;

    @Override
    public RefreshSession save(RefreshSession session) {
        RefreshSession saved = copy(session);
        if (saved.getId() == null) saved.setId(nextId++);
        nextId = Math.max(nextId, saved.getId() + 1);
        sessions.put(saved.getId(), saved);
        return copy(saved);
    }

    @Override
    public List<RefreshSession> saveAll(List<RefreshSession> values) {
        return values.stream().map(this::save).toList();
    }

    @Override
    public Optional<RefreshSession> findById(Long id) {
        return Optional.ofNullable(sessions.get(id)).map(InMemoryRefreshSessionStore::copy);
    }

    @Override
    public Optional<RefreshSession> findByTokenHash(String hash) {
        return sessions.values().stream().filter(s -> Objects.equals(hash, s.getTokenHash()))
                .findFirst().map(InMemoryRefreshSessionStore::copy);
    }

    @Override
    public List<RefreshSession> findActiveByUsername(String username) {
        return select(s -> !s.isRevoked() && Objects.equals(username, s.getUsername()));
    }

    @Override
    public List<RefreshSession> findActiveByUsernameOrderByCreatedAtDesc(String username) {
        return findActiveByUsername(username).stream()
                .sorted(Comparator.comparing(RefreshSession::getCreatedAt).reversed()).toList();
    }

    @Override
    public List<RefreshSession> findExpiredActiveSessions(Instant now) {
        return select(s -> !s.isRevoked() && s.getExpiresAt().isBefore(now));
    }

    @Override
    public void deleteById(Long id) { sessions.remove(id); }

    private List<RefreshSession> select(Predicate<RefreshSession> predicate) {
        return sessions.values().stream().filter(predicate).map(InMemoryRefreshSessionStore::copy).toList();
    }

    private static RefreshSession copy(RefreshSession value) {
        return RefreshSession.builder().id(value.getId()).username(value.getUsername()).tokenHash(value.getTokenHash())
                .createdAt(value.getCreatedAt()).expiresAt(value.getExpiresAt()).lastUsedAt(value.getLastUsedAt())
                .revoked(value.isRevoked()).revokedAt(value.getRevokedAt()).revocationReason(value.getRevocationReason())
                .replacedByTokenHash(value.getReplacedByTokenHash()).ip(value.getIp()).userAgent(value.getUserAgent()).build();
    }
}

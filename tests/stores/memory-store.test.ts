/**
 * jts-core - Session Store Tests
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { InMemorySessionStore } from '../../src/stores/memory-store';
import { JTSSession } from '../../src/types';

describe('InMemorySessionStore', () => {
  let store: InMemorySessionStore;

  beforeEach(() => {
    store = new InMemorySessionStore({
      rotationGraceWindow: 10, // 10 seconds
      defaultSessionLifetime: 3600, // 1 hour
    });
  });

  afterEach(async () => {
    await store.close();
    vi.useRealTimers();
  });

  describe('createSession', () => {
    it('should create a new session', async () => {
      const session = await store.createSession({
        prn: 'user123',
        deviceFingerprint: 'sha256:abc123',
        userAgent: 'Mozilla/5.0',
        ipAddress: '192.168.1.1',
      });

      expect(session.aid).toMatch(/^aid_/);
      expect(session.prn).toBe('user123');
      expect(session.currentStateProof).toMatch(/^sp_/);
      expect(session.deviceFingerprint).toBe('sha256:abc123');
      expect(session.stateProofVersion).toBe(1);
      expect(session.createdAt).toBeInstanceOf(Date);
      expect(session.expiresAt).toBeInstanceOf(Date);
      expect(session.lastActive).toBeInstanceOf(Date);
    });

    it('should create session with custom expiration', async () => {
      const session = await store.createSession({
        prn: 'user123',
        expiresIn: 300, // 5 minutes
      });

      const expectedExpiry = session.createdAt.getTime() + 300 * 1000;
      expect(Math.abs(session.expiresAt.getTime() - expectedExpiry)).toBeLessThan(100);
    });

    it('should create session with metadata', async () => {
      const session = await store.createSession({
        prn: 'user123',
        metadata: {
          role: 'admin',
          customData: 42,
        },
      });

      expect(session.metadata).toEqual({
        role: 'admin',
        customData: 42,
      });
    });

    it('should create unique sessions', async () => {
      const session1 = await store.createSession({ prn: 'user123' });
      const session2 = await store.createSession({ prn: 'user123' });

      expect(session1.aid).not.toBe(session2.aid);
      expect(session1.currentStateProof).not.toBe(session2.currentStateProof);
    });
  });

  describe('getSessionByAid', () => {
    it('should retrieve session by aid', async () => {
      const created = await store.createSession({ prn: 'user123' });
      const retrieved = await store.getSessionByAid(created.aid);

      expect(retrieved).toBeDefined();
      expect(retrieved?.aid).toBe(created.aid);
      expect(retrieved?.prn).toBe('user123');
    });

    it('should return null for non-existent session', async () => {
      const result = await store.getSessionByAid('aid_nonexistent');
      expect(result).toBeNull();
    });

    it('should return null for expired session', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      const session = await store.createSession({
        prn: 'user123',
        expiresIn: 60, // 1 minute
      });

      // Advance time past expiration
      vi.setSystemTime(now + 120 * 1000);

      const result = await store.getSessionByAid(session.aid);
      expect(result).toBeNull();
    });
  });

  describe('getSessionByStateProof', () => {
    it('should validate current StateProof', async () => {
      const session = await store.createSession({ prn: 'user123' });

      const result = await store.getSessionByStateProof(session.currentStateProof);

      expect(result.valid).toBe(true);
      expect(result.session?.aid).toBe(session.aid);
      expect(result.withinGraceWindow).toBe(false);
    });

    it('should validate previous StateProof within grace window', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      const session = await store.createSession({ prn: 'user123' });
      const oldStateProof = session.currentStateProof;

      // Rotate StateProof
      await store.rotateStateProof(session.aid);

      // Check within grace window
      vi.setSystemTime(now + 5000); // 5 seconds

      const result = await store.getSessionByStateProof(oldStateProof);

      expect(result.valid).toBe(true);
      expect(result.withinGraceWindow).toBe(true);
    });

    it('should detect replay attack (previous StateProof after grace window)', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      const session = await store.createSession({ prn: 'user123' });
      const oldStateProof = session.currentStateProof;

      // Rotate StateProof
      await store.rotateStateProof(session.aid);

      // Advance time past grace window
      vi.setSystemTime(now + 15000); // 15 seconds (> 10 second grace)

      const result = await store.getSessionByStateProof(oldStateProof);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('JTS-401-05'); // session_compromised
    });

    it('should reject invalid StateProof', async () => {
      await store.createSession({ prn: 'user123' });

      const result = await store.getSessionByStateProof('sp_invalid');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('JTS-401-03'); // stateproof_invalid
    });
  });

  describe('rotateStateProof', () => {
    it('should rotate StateProof and preserve previous', async () => {
      const session = await store.createSession({ prn: 'user123' });
      const oldStateProof = session.currentStateProof;

      const rotated = await store.rotateStateProof(session.aid);

      expect(rotated.currentStateProof).not.toBe(oldStateProof);
      expect(rotated.previousStateProof).toBe(oldStateProof);
      expect(rotated.stateProofVersion).toBe(2);
      expect(rotated.rotationTimestamp).toBeInstanceOf(Date);
    });

    it('should accept custom new StateProof', async () => {
      const session = await store.createSession({ prn: 'user123' });
      
      const rotated = await store.rotateStateProof(session.aid, 'sp_custom');

      expect(rotated.currentStateProof).toBe('sp_custom');
    });

    it('should throw for non-existent session', async () => {
      await expect(store.rotateStateProof('aid_nonexistent')).rejects.toThrow();
    });

    it('should update lastActive on rotation', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      const session = await store.createSession({ prn: 'user123' });
      const initialLastActive = session.lastActive.getTime();
      
      vi.setSystemTime(now + 60000); // 1 minute later

      const rotated = await store.rotateStateProof(session.aid);

      // lastActive should be updated to the new time
      expect(rotated.lastActive.getTime()).toBeGreaterThanOrEqual(initialLastActive);
    });
  });

  describe('touchSession', () => {
    it('should update lastActive timestamp', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      const session = await store.createSession({ prn: 'user123' });
      const initialLastActive = session.lastActive.getTime();

      vi.setSystemTime(now + 30000); // 30 seconds later

      await store.touchSession(session.aid);

      const updated = await store.getSessionByAid(session.aid);
      expect(updated?.lastActive.getTime()).toBeGreaterThan(initialLastActive);
    });

    it('should not throw for non-existent session', async () => {
      await expect(store.touchSession('aid_nonexistent')).resolves.not.toThrow();
    });
  });

  describe('deleteSession', () => {
    it('should delete session', async () => {
      const session = await store.createSession({ prn: 'user123' });

      const deleted = await store.deleteSession(session.aid);
      expect(deleted).toBe(true);

      const result = await store.getSessionByAid(session.aid);
      expect(result).toBeNull();
    });

    it('should return false for non-existent session', async () => {
      const deleted = await store.deleteSession('aid_nonexistent');
      expect(deleted).toBe(false);
    });

    it('should invalidate StateProof after deletion', async () => {
      const session = await store.createSession({ prn: 'user123' });
      const stateProof = session.currentStateProof;

      await store.deleteSession(session.aid);

      const result = await store.getSessionByStateProof(stateProof);
      expect(result.valid).toBe(false);
    });
  });

  describe('deleteAllSessionsForPrincipal', () => {
    it('should delete all sessions for a user', async () => {
      await store.createSession({ prn: 'user123' });
      await store.createSession({ prn: 'user123' });
      await store.createSession({ prn: 'other-user' });

      const deleted = await store.deleteAllSessionsForPrincipal('user123');

      expect(deleted).toBe(2);
      expect(store.getSize()).toBe(1);
    });

    it('should return 0 if no sessions found', async () => {
      const deleted = await store.deleteAllSessionsForPrincipal('nonexistent');
      expect(deleted).toBe(0);
    });
  });

  describe('getSessionsForPrincipal', () => {
    it('should return all sessions for a user', async () => {
      await store.createSession({ prn: 'user123' });
      await store.createSession({ prn: 'user123' });
      await store.createSession({ prn: 'other-user' });

      const sessions = await store.getSessionsForPrincipal('user123');

      expect(sessions).toHaveLength(2);
      sessions.forEach(s => expect(s.prn).toBe('user123'));
    });

    it('should return sessions sorted by lastActive (most recent first)', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      const s1 = await store.createSession({ prn: 'user123' });
      vi.setSystemTime(now + 10000);
      await store.createSession({ prn: 'user123' });
      vi.setSystemTime(now + 20000);
      await store.touchSession(s1.aid);

      const sessions = await store.getSessionsForPrincipal('user123');

      expect(sessions[0].aid).toBe(s1.aid); // Most recently active
    });

    it('should not return expired sessions', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      await store.createSession({
        prn: 'user123',
        expiresIn: 60,
      });
      await store.createSession({
        prn: 'user123',
        expiresIn: 300,
      });

      vi.setSystemTime(now + 120 * 1000);

      const sessions = await store.getSessionsForPrincipal('user123');
      expect(sessions).toHaveLength(1);
    });

    it('should return empty array if no sessions', async () => {
      const sessions = await store.getSessionsForPrincipal('nonexistent');
      expect(sessions).toEqual([]);
    });
  });

  describe('countSessionsForPrincipal', () => {
    it('should count active sessions', async () => {
      await store.createSession({ prn: 'user123' });
      await store.createSession({ prn: 'user123' });
      await store.createSession({ prn: 'other-user' });

      const count = await store.countSessionsForPrincipal('user123');
      expect(count).toBe(2);
    });

    it('should return 0 if no sessions', async () => {
      const count = await store.countSessionsForPrincipal('nonexistent');
      expect(count).toBe(0);
    });
  });

  describe('deleteOldestSessionForPrincipal', () => {
    it('should delete the oldest session', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      const oldest = await store.createSession({ prn: 'user123' });
      vi.setSystemTime(now + 10000);
      const newer = await store.createSession({ prn: 'user123' });

      const deleted = await store.deleteOldestSessionForPrincipal('user123');
      expect(deleted).toBe(true);

      const remaining = await store.getSessionsForPrincipal('user123');
      expect(remaining).toHaveLength(1);
      expect(remaining[0].aid).toBe(newer.aid);
    });

    it('should return false if no sessions', async () => {
      const deleted = await store.deleteOldestSessionForPrincipal('nonexistent');
      expect(deleted).toBe(false);
    });
  });

  describe('cleanupExpiredSessions', () => {
    it('should remove expired sessions', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      await store.createSession({
        prn: 'user123',
        expiresIn: 60,
      });
      await store.createSession({
        prn: 'user123',
        expiresIn: 300,
      });

      vi.setSystemTime(now + 120 * 1000);

      const cleaned = await store.cleanupExpiredSessions();
      expect(cleaned).toBe(1);
      expect(store.getSize()).toBe(1);
    });

    it('should return 0 if no expired sessions', async () => {
      await store.createSession({ prn: 'user123' });

      const cleaned = await store.cleanupExpiredSessions();
      expect(cleaned).toBe(0);
    });
  });

  describe('healthCheck', () => {
    it('should return true', async () => {
      const healthy = await store.healthCheck();
      expect(healthy).toBe(true);
    });
  });

  describe('close / clear', () => {
    it('should clear all data on close', async () => {
      await store.createSession({ prn: 'user123' });
      await store.createSession({ prn: 'user456' });

      await store.close();

      expect(store.getSize()).toBe(0);
    });

    it('should clear all data on clear', async () => {
      await store.createSession({ prn: 'user123' });

      await store.clear();

      expect(store.getSize()).toBe(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle rapid StateProof rotations', async () => {
      const session = await store.createSession({ prn: 'user123' });

      for (let i = 0; i < 10; i++) {
        await store.rotateStateProof(session.aid);
      }

      const updated = await store.getSessionByAid(session.aid);
      expect(updated?.stateProofVersion).toBe(11);
    });

    it('should handle concurrent session creation', async () => {
      const promises = Array.from({ length: 100 }, () =>
        store.createSession({ prn: 'user123' })
      );

      const sessions = await Promise.all(promises);
      const uniqueAids = new Set(sessions.map(s => s.aid));

      expect(uniqueAids.size).toBe(100);
    });

    it('should handle special characters in metadata', async () => {
      const session = await store.createSession({
        prn: 'user123',
        metadata: {
          'key with spaces': 'value',
          'unicode': '日本語',
          'emoji': '🔐',
        },
      });

      const retrieved = await store.getSessionByAid(session.aid);
      expect(retrieved?.metadata?.['key with spaces']).toBe('value');
      expect(retrieved?.metadata?.['unicode']).toBe('日本語');
      expect(retrieved?.metadata?.['emoji']).toBe('🔐');
    });
  });
});

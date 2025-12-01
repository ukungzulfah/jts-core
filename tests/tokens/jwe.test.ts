/**
 * @engjts/auth - JWE (JTS-C Profile) Tests
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  createEncryptedBearerPass,
  decryptJWE,
  verifyEncryptedBearerPass,
  isEncryptedToken,
} from '../../src/tokens/jwe';
import { createBearerPass, decodeBearerPass } from '../../src/tokens/bearer-pass';
import { generateKeyPair } from '../../src/crypto';
import { JTSError, JTSKeyPair } from '../../src/types';

describe('JWE (JTS-C Profile)', () => {
  let signingKey: JTSKeyPair;
  let encryptionKey: JTSKeyPair;
  let otherEncryptionKey: JTSKeyPair;

  beforeAll(async () => {
    signingKey = await generateKeyPair('jwe-sign-key', 'RS256');
    encryptionKey = await generateKeyPair('jwe-enc-key', 'RS256');
    otherEncryptionKey = await generateKeyPair('other-enc-key', 'RS256');
  });

  describe('createEncryptedBearerPass', () => {
    it('should create encrypted JWE token', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      expect(token).toBeDefined();
      expect(token.split('.')).toHaveLength(5); // JWE has 5 parts
    });

    it('should create JWE with correct header', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      // Parse just the header (first part)
      const [headerPart] = token.split('.');
      const header = JSON.parse(
        Buffer.from(headerPart.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()
      );

      expect(header.typ).toBe('JTS-C/v1');
      expect(header.alg).toBe('RSA-OAEP-256');
      expect(header.enc).toBe('A256GCM');
      expect(header.kid).toBe(encryptionKey.kid);
    });

    it('should include custom encryption algorithm', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionAlgorithm: 'RSA-OAEP-256',
        contentEncryption: 'A256GCM',
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      expect(token.split('.')).toHaveLength(5);
    });

    it('should produce different ciphertext each time (randomized)', () => {
      const options = {
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      };

      const token1 = createEncryptedBearerPass(options);
      const token2 = createEncryptedBearerPass(options);

      // Different IV and CEK mean different ciphertext
      expect(token1).not.toBe(token2);
    });

    it('should include all payload claims', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: {
          perm: ['read', 'write'],
          dfp: 'sha256:fingerprint',
        },
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      // Decrypt and verify payload is intact
      const { jws } = decryptJWE({
        token,
        decryptionKey: {
          kid: encryptionKey.kid,
          privateKey: encryptionKey.privateKey!,
        },
      });

      const decoded = decodeBearerPass(jws);
      expect(decoded.payload.perm).toEqual(['read', 'write']);
      expect(decoded.payload.dfp).toBe('sha256:fingerprint');
    });
  });

  describe('decryptJWE', () => {
    it('should decrypt JWE to get inner JWS', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      const { jws, header } = decryptJWE({
        token,
        decryptionKey: {
          kid: encryptionKey.kid,
          privateKey: encryptionKey.privateKey!,
        },
      });

      expect(jws).toBeDefined();
      expect(jws.split('.')).toHaveLength(3); // JWS has 3 parts
      expect(header.typ).toBe('JTS-C/v1');
    });

    it('should throw on invalid JWE format', () => {
      expect(() =>
        decryptJWE({
          token: 'only.four.parts.here',
          decryptionKey: {
            kid: encryptionKey.kid,
            privateKey: encryptionKey.privateKey!,
          },
        })
      ).toThrow(JTSError);
    });

    it('should throw on wrong decryption key', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      expect(() =>
        decryptJWE({
          token,
          decryptionKey: {
            kid: otherEncryptionKey.kid,
            privateKey: otherEncryptionKey.privateKey!,
          },
        })
      ).toThrow(JTSError);
    });

    it('should throw on key ID mismatch', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      expect(() =>
        decryptJWE({
          token,
          decryptionKey: {
            kid: 'wrong-kid',
            privateKey: encryptionKey.privateKey!,
          },
        })
      ).toThrow(JTSError);
    });

    it('should throw on non-JTS-C token type', () => {
      // Create a fake JWE-like token with wrong type
      const header = Buffer.from(JSON.stringify({
        alg: 'RSA-OAEP-256',
        enc: 'A256GCM',
        typ: 'JWT', // Wrong type
        kid: encryptionKey.kid,
      })).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

      const fakeToken = `${header}.aaaa.bbbb.cccc.dddd`;

      expect(() =>
        decryptJWE({
          token: fakeToken,
          decryptionKey: {
            kid: encryptionKey.kid,
            privateKey: encryptionKey.privateKey!,
          },
        })
      ).toThrow(JTSError);
    });

    it('should throw on tampered ciphertext', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      const parts = token.split('.');
      parts[3] = parts[3].slice(0, -4) + 'XXXX'; // Tamper with ciphertext
      const tamperedToken = parts.join('.');

      expect(() =>
        decryptJWE({
          token: tamperedToken,
          decryptionKey: {
            kid: encryptionKey.kid,
            privateKey: encryptionKey.privateKey!,
          },
        })
      ).toThrow();
    });
  });

  describe('verifyEncryptedBearerPass', () => {
    it('should decrypt and verify valid token', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      const result = verifyEncryptedBearerPass({
        token,
        decryptionKey: {
          kid: encryptionKey.kid,
          privateKey: encryptionKey.privateKey!,
        },
        publicKeys: new Map([[signingKey.kid, signingKey]]),
      });

      expect(result.valid).toBe(true);
      expect(result.payload?.prn).toBe('user123');
    });

    it('should fail if decryption fails', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      const result = verifyEncryptedBearerPass({
        token,
        decryptionKey: {
          kid: otherEncryptionKey.kid,
          privateKey: otherEncryptionKey.privateKey!,
        },
        publicKeys: new Map([[signingKey.kid, signingKey]]),
      });

      expect(result.valid).toBe(false);
    });

    it('should fail if inner JWS signature is invalid', async () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      // Use wrong signing key for verification
      const otherSigningKey = await generateKeyPair('other-sign', 'RS256');

      const result = verifyEncryptedBearerPass({
        token,
        decryptionKey: {
          kid: encryptionKey.kid,
          privateKey: encryptionKey.privateKey!,
        },
        publicKeys: new Map([[otherSigningKey.kid, otherSigningKey]]),
      });

      expect(result.valid).toBe(false);
      expect(result.error?.errorCode).toBe('JTS-500-01');
    });

    it('should validate permissions', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: { perm: ['read'] },
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      const result = verifyEncryptedBearerPass({
        token,
        decryptionKey: {
          kid: encryptionKey.kid,
          privateKey: encryptionKey.privateKey!,
        },
        publicKeys: new Map([[signingKey.kid, signingKey]]),
      });

      expect(result.valid).toBe(true);
      expect(result.payload?.perm).toEqual(['read']);
    });
  });

  describe('isEncryptedToken', () => {
    it('should return true for JWE tokens', () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      expect(isEncryptedToken(token)).toBe(true);
    });

    it('should return false for JWS tokens', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        profile: 'JTS-S/v1',
      });

      expect(isEncryptedToken(token)).toBe(false);
    });

    it('should return false for invalid tokens', () => {
      expect(isEncryptedToken('invalid')).toBe(false);
      expect(isEncryptedToken('a.b.c')).toBe(false);
      expect(isEncryptedToken('')).toBe(false);
    });

    it('should return false for 5-part token with wrong type', () => {
      const header = Buffer.from(JSON.stringify({
        alg: 'RSA-OAEP',
        enc: 'A256GCM',
        typ: 'JWT',
      })).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

      const fakeToken = `${header}.a.b.c.d`;
      expect(isEncryptedToken(fakeToken)).toBe(false);
    });
  });
});

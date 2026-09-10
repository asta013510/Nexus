/**
 * Tests for @zero/crypto package
 * Validates cryptographic functions: hashing, TOTP, JWT, encryption
 */
import { describe, it, expect } from 'vitest';
import { hashPassword, verifyPassword, generateTOTPSecret, generateTOTP, verifyTOTP, generateAccessToken, generateRefreshToken, verifyJWT, decodeJWT, encrypt, decrypt, generateRecoveryCodes, } from './index';
describe('@zero/crypto', () => {
    describe('hashPassword & verifyPassword', () => {
        it('should hash a password successfully', async () => {
            const password = 'SecureP@ssw0rd123!';
            const hash = await hashPassword(password);
            expect(hash).toBeDefined();
            expect(hash.length).toBeGreaterThan(50);
            expect(hash).not.toBe(password);
        });
        it('should verify correct password', async () => {
            const password = 'SecureP@ssw0rd123!';
            const hash = await hashPassword(password);
            const isValid = await verifyPassword(password, hash);
            expect(isValid).toBe(true);
        });
        it('should reject incorrect password', async () => {
            const password = 'SecureP@ssw0rd123!';
            const wrongPassword = 'WrongP@ssw0rd456!';
            const hash = await hashPassword(password);
            const isValid = await verifyPassword(wrongPassword, hash);
            expect(isValid).toBe(false);
        });
        it('should produce different hashes for same password', async () => {
            const password = 'SecureP@ssw0rd123!';
            const hash1 = await hashPassword(password);
            const hash2 = await hashPassword(password);
            expect(hash1).not.toBe(hash2);
        });
        it('should handle unicode passwords', async () => {
            const password = 'SëcürëPässwörd123! 🔐';
            const hash = await hashPassword(password);
            const isValid = await verifyPassword(password, hash);
            expect(isValid).toBe(true);
        });
    });
    describe('generateTOTPSecret & verifyTOTP', () => {
        it('should generate a valid TOTP secret', () => {
            const result = generateTOTPSecret();
            const secret = result.secret;
            expect(secret).toBeDefined();
            expect(secret.length).toBeGreaterThanOrEqual(32);
            expect(/^[A-Z2-7]+$/.test(secret)).toBe(true); // Base32 encoding
        });
        it('should generate unique secrets', () => {
            const result1 = generateTOTPSecret();
            const result2 = generateTOTPSecret();
            expect(result1.secret).not.toBe(result2.secret);
        });
        it('should verify current TOTP code', async () => {
            const result = generateTOTPSecret();
            const code = await generateTOTP(result.secret);
            const isValid = await verifyTOTP(result.secret, code);
            expect(isValid).toBe(true);
        });
        it('should reject invalid TOTP code', async () => {
            const result = generateTOTPSecret();
            const invalidCode = '000000';
            const isValid = await verifyTOTP(result.secret, invalidCode);
            expect(isValid).toBe(false);
        });
        it('should accept codes within time window (drift)', async () => {
            const result = generateTOTPSecret();
            const code = await generateTOTP(result.secret);
            // Verify with default drift (1 step before/after)
            const isValid = await verifyTOTP(result.secret, code, 1);
            expect(isValid).toBe(true);
        });
    });
    describe('JWT Functions', () => {
        const testUserId = 'user-123';
        const testSessionId = 'session-456';
        const testDeviceId = 'device-789';
        const testEmail = 'test@zero.security';
        it('should generate access token', async () => {
            const payload = {
                userId: testUserId,
                sessionId: testSessionId,
                deviceId: testDeviceId,
                email: testEmail,
            };
            const token = await generateAccessToken(payload);
            expect(token).toBeDefined();
            expect(token.split('.').length).toBe(3); // JWT has 3 parts
        });
        it('should generate refresh token', async () => {
            const payload = {
                userId: testUserId,
                sessionId: testSessionId,
                deviceId: testDeviceId,
                jti: `jti-${Date.now()}`,
            };
            const token = await generateRefreshToken(payload);
            expect(token).toBeDefined();
            expect(token.split('.').length).toBe(3);
        });
        it('should verify valid access token', async () => {
            const payload = {
                userId: testUserId,
                sessionId: testSessionId,
                deviceId: testDeviceId,
                email: testEmail,
            };
            const token = await generateAccessToken(payload);
            const result = await verifyJWT(token);
            expect(result.valid).toBe(true);
            expect(result.payload?.userId).toBe(testUserId);
            if ('email' in result.payload) {
                expect(result.payload.email).toBe(testEmail);
            }
        });
        it('should verify valid refresh token', async () => {
            const payload = {
                userId: testUserId,
                sessionId: testSessionId,
                deviceId: testDeviceId,
                jti: `jti-${Date.now()}`,
            };
            const token = await generateRefreshToken(payload);
            const result = await verifyJWT(token);
            expect(result.valid).toBe(true);
            expect(result.payload?.userId).toBe(testUserId);
        });
        it('should decode token without verification', async () => {
            const payload = {
                userId: testUserId,
                sessionId: testSessionId,
                deviceId: testDeviceId,
                email: testEmail,
            };
            const token = await generateAccessToken(payload);
            const decoded = await decodeJWT(token);
            expect(decoded).toBeDefined();
            if (decoded && 'userId' in decoded) {
                expect(decoded.userId).toBe(testUserId);
            }
        });
        it('should include standard JWT claims', async () => {
            const payload = {
                userId: testUserId,
                sessionId: testSessionId,
                deviceId: testDeviceId,
                email: testEmail,
            };
            const token = await generateAccessToken(payload);
            const decoded = await decodeJWT(token);
            expect(decoded?.payload.iat).toBeDefined();
            expect(decoded?.payload.exp).toBeDefined();
            expect(decoded?.payload.iss).toBe('zero-security');
            expect(decoded?.payload.aud).toBe('zero-app');
        });
    });
    describe('encrypt & decrypt', () => {
        const testKeyHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // 64 hex chars = 32 bytes
        const testData = 'Sensitive data to encrypt 🔐';
        it('should encrypt data successfully', async () => {
            const key = await crypto.subtle.importKey('raw', Buffer.from(testKeyHex, 'hex'), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
            const encrypted = await encrypt(testData, key);
            expect(encrypted).toBeDefined();
            expect(encrypted.ciphertext).not.toBe(testData);
            expect(encrypted.iv).toBeDefined();
            expect(encrypted.tag).toBeDefined();
        });
        it('should decrypt data correctly', async () => {
            const key = await crypto.subtle.importKey('raw', Buffer.from(testKeyHex, 'hex'), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
            const encrypted = await encrypt(testData, key);
            const decrypted = await decrypt(encrypted.ciphertext, encrypted.iv, encrypted.tag, key);
            expect(decrypted).toBe(testData);
        });
        it('should produce different ciphertexts for same plaintext', async () => {
            const key = await crypto.subtle.importKey('raw', Buffer.from(testKeyHex, 'hex'), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
            const encrypted1 = await encrypt(testData, key);
            const encrypted2 = await encrypt(testData, key);
            expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext); // Due to random IV
        });
        it('should reject decryption with wrong key', async () => {
            const correctKey = await crypto.subtle.importKey('raw', Buffer.from(testKeyHex, 'hex'), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
            const wrongKey = await crypto.subtle.importKey('raw', Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex'), { name: 'AES-GCM' }, false, ['decrypt']);
            const encrypted = await encrypt(testData, correctKey);
            await expect(decrypt(encrypted.ciphertext, encrypted.iv, encrypted.tag, wrongKey)).rejects.toThrow();
        });
        it('should reject decryption of tampered data', async () => {
            const key = await crypto.subtle.importKey('raw', Buffer.from(testKeyHex, 'hex'), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
            const encrypted = await encrypt(testData, key);
            const tampered = encrypted.ciphertext + 'tampered';
            await expect(decrypt(tampered, encrypted.iv, encrypted.tag, key)).rejects.toThrow();
        });
        it('should handle empty string', async () => {
            const key = await crypto.subtle.importKey('raw', Buffer.from(testKeyHex, 'hex'), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
            const encrypted = await encrypt('', key);
            const decrypted = await decrypt(encrypted.ciphertext, encrypted.iv, encrypted.tag, key);
            expect(decrypted).toBe('');
        });
        it('should handle unicode data', async () => {
            const unicodeData = 'Dados sensíveis em português 🔐 中文 🎉';
            const key = await crypto.subtle.importKey('raw', Buffer.from(testKeyHex, 'hex'), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
            const encrypted = await encrypt(unicodeData, key);
            const decrypted = await decrypt(encrypted.ciphertext, encrypted.iv, encrypted.tag, key);
            expect(decrypted).toBe(unicodeData);
        });
    });
    describe('Recovery Codes', () => {
        it('should generate recovery codes', () => {
            const codes = generateRecoveryCodes(8);
            expect(codes).toHaveLength(8);
            codes.forEach(code => {
                expect(code).toMatch(/^[0-9]{4}-[0-9]{4}-[0-9]{4}$/);
            });
        });
        it('should generate unique codes', () => {
            const codes = generateRecoveryCodes(10);
            const uniqueCodes = new Set(codes);
            expect(uniqueCodes.size).toBe(codes.length);
        });
        it('should support different code counts', () => {
            const codes5 = generateRecoveryCodes(5);
            const codes10 = generateRecoveryCodes(10);
            const codes16 = generateRecoveryCodes(16);
            expect(codes5).toHaveLength(5);
            expect(codes10).toHaveLength(10);
            expect(codes16).toHaveLength(16);
        });
    });
});
//# sourceMappingURL=index.test.js.map
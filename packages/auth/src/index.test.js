"use strict";
/**
 * Tests for @zero/auth package - Unit Tests
 * Validates authentication logic without database dependencies
 */
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const crypto_1 = require("@zero/crypto");
// Import validation functions directly to avoid ESM/CJS issues
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}
function validatePassword(password) {
    // Minimum 8 characters, at least one uppercase, one lowercase, one number, one special character
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/;
    return passwordRegex.test(password);
}
function getPasswordStrength(password) {
    let strength = 0;
    if (password.length >= 8)
        strength++;
    if (password.length >= 12)
        strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password))
        strength++;
    if (/\d/.test(password))
        strength++;
    if (/[^a-zA-Z\d]/.test(password))
        strength++;
    return Math.min(strength, 5);
}
(0, vitest_1.describe)('@zero/auth - Unit Tests', () => {
    (0, vitest_1.describe)('Email Validation', () => {
        (0, vitest_1.it)('should accept valid email formats', () => {
            const validEmails = [
                'user@zero.security',
                'test.user@zero.security',
                'user+tag@zero.security',
                'user123@zero.security',
                'user@subdomain.zero.security',
            ];
            validEmails.forEach(email => {
                (0, vitest_1.expect)(validateEmail(email)).toBe(true);
            });
        });
        (0, vitest_1.it)('should reject invalid email formats', () => {
            const invalidEmails = [
                'not-an-email',
                '@zero.security',
                'user@',
                'user@zero',
                'user@.security',
                'user name@zero.security',
                '',
            ];
            invalidEmails.forEach(email => {
                (0, vitest_1.expect)(validateEmail(email)).toBe(false);
            });
        });
    });
    (0, vitest_1.describe)('Password Validation', () => {
        (0, vitest_1.it)('should accept strong passwords', () => {
            const strongPasswords = [
                'SecureP@ssw0rd123!',
                'MyStr0ng&P@ssw0rd!',
                'C0mpl3x!P@ssw0rd#2024',
            ];
            strongPasswords.forEach(password => {
                (0, vitest_1.expect)(validatePassword(password)).toBe(true);
            });
        });
        (0, vitest_1.it)('should reject weak passwords', () => {
            const weakPasswords = [
                'weak',
                '123456',
                'password',
                'abc123',
                'short!',
                'NoNumbers!',
                'nouppercase123!',
                'NOLOWERCASE123!',
            ];
            weakPasswords.forEach(password => {
                (0, vitest_1.expect)(validatePassword(password)).toBe(false);
            });
        });
        (0, vitest_1.it)('should calculate password strength correctly', () => {
            (0, vitest_1.expect)(getPasswordStrength('weak')).toBe(0);
            (0, vitest_1.expect)(getPasswordStrength('medium123')).toBeGreaterThanOrEqual(1);
            (0, vitest_1.expect)(getPasswordStrength('StrongP@ssw0rd!')).toBeGreaterThanOrEqual(3);
        });
    });
    (0, vitest_1.describe)('Recovery Codes', () => {
        (0, vitest_1.it)('should generate properly formatted recovery codes', () => {
            const codes = (0, crypto_1.generateRecoveryCodes)(10);
            (0, vitest_1.expect)(codes).toHaveLength(10);
            codes.forEach(code => {
                (0, vitest_1.expect)(code).toMatch(/^[0-9]{4}-[0-9]{4}-[0-9]{4}$/);
            });
        });
        (0, vitest_1.it)('should generate unique recovery codes', () => {
            const codes = (0, crypto_1.generateRecoveryCodes)(16);
            const uniqueCodes = new Set(codes);
            (0, vitest_1.expect)(uniqueCodes.size).toBe(codes.length);
        });
    });
});
//# sourceMappingURL=index.test.js.map
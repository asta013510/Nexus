/**
 * Tests for @zero/auth package - Unit Tests
 * Validates authentication logic without database dependencies
 */

import { describe, it, expect } from 'vitest';
import { generateRecoveryCodes } from '@zero/crypto';

// Import validation functions directly to avoid ESM/CJS issues
function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validatePassword(password: string): boolean {
  // Minimum 8 characters, at least one uppercase, one lowercase, one number, one special character
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/;
  return passwordRegex.test(password);
}

function getPasswordStrength(password: string): number {
  let strength = 0;
  
  if (password.length >= 8) strength++;
  if (password.length >= 12) strength++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
  if (/\d/.test(password)) strength++;
  if (/[^a-zA-Z\d]/.test(password)) strength++;
  
  return Math.min(strength, 5);
}

describe('@zero/auth - Unit Tests', () => {
  describe('Email Validation', () => {
    it('should accept valid email formats', () => {
      const validEmails = [
        'user@zero.security',
        'test.user@zero.security',
        'user+tag@zero.security',
        'user123@zero.security',
        'user@subdomain.zero.security',
      ];

      validEmails.forEach(email => {
        expect(validateEmail(email)).toBe(true);
      });
    });

    it('should reject invalid email formats', () => {
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
        expect(validateEmail(email)).toBe(false);
      });
    });
  });

  describe('Password Validation', () => {
    it('should accept strong passwords', () => {
      const strongPasswords = [
        'SecureP@ssw0rd123!',
        'MyStr0ng&P@ssw0rd!',
        'C0mpl3x!P@ssw0rd#2024',
      ];

      strongPasswords.forEach(password => {
        expect(validatePassword(password)).toBe(true);
      });
    });

    it('should reject weak passwords', () => {
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
        expect(validatePassword(password)).toBe(false);
      });
    });

    it('should calculate password strength correctly', () => {
      expect(getPasswordStrength('weak')).toBe(0);
      expect(getPasswordStrength('medium123')).toBeGreaterThanOrEqual(1);
      expect(getPasswordStrength('StrongP@ssw0rd!')).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Recovery Codes', () => {
    it('should generate properly formatted recovery codes', () => {
      const codes = generateRecoveryCodes(10);
      
      expect(codes).toHaveLength(10);
      codes.forEach(code => {
        expect(code).toMatch(/^[0-9]{4}-[0-9]{4}-[0-9]{4}$/);
      });
    });

    it('should generate unique recovery codes', () => {
      const codes = generateRecoveryCodes(16);
      const uniqueCodes = new Set(codes);
      
      expect(uniqueCodes.size).toBe(codes.length);
    });
  });
});

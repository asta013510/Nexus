/**
 * Setup file for Jest tests
 * Configures global test environment and utilities
 */

import { beforeAll, afterAll, afterEach } from '@jest/globals';

// Global timeout for async operations
jest.setTimeout(30000);

// Mock console.error in tests to avoid noise (can be overridden per test)
const originalConsoleError = console.error;
beforeAll(() => {
  console.error = jest.fn();
});

afterEach(() => {
  jest.clearAllMocks();
});

afterAll(() => {
  console.error = originalConsoleError;
});

// Global test utilities
export const TEST_EMAIL_DOMAIN = '@test.zero.security';
export const generateTestEmail = (prefix: string): string => {
  return `${prefix}${Date.now()}${TEST_EMAIL_DOMAIN}`;
};

export const TEST_PASSWORD = 'SecureP@ssw0rd123!';
export const TEST_USER_NAME = 'Test User';

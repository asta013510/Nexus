"use strict";
/**
 * Setup file for Jest tests
 * Configures global test environment and utilities
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.TEST_USER_NAME = exports.TEST_PASSWORD = exports.generateTestEmail = exports.TEST_EMAIL_DOMAIN = void 0;
const globals_1 = require("@jest/globals");
// Global timeout for async operations
jest.setTimeout(30000);
// Mock console.error in tests to avoid noise (can be overridden per test)
const originalConsoleError = console.error;
(0, globals_1.beforeAll)(() => {
    console.error = jest.fn();
});
(0, globals_1.afterEach)(() => {
    jest.clearAllMocks();
});
(0, globals_1.afterAll)(() => {
    console.error = originalConsoleError;
});
// Global test utilities
exports.TEST_EMAIL_DOMAIN = '@test.zero.security';
const generateTestEmail = (prefix) => {
    return `${prefix}${Date.now()}${exports.TEST_EMAIL_DOMAIN}`;
};
exports.generateTestEmail = generateTestEmail;
exports.TEST_PASSWORD = 'SecureP@ssw0rd123!';
exports.TEST_USER_NAME = 'Test User';
//# sourceMappingURL=setup.js.map
"use strict";
/**
 * Constantes de Autenticação
 *
 * Valores configuráveis para segurança e comportamento do sistema de auth
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PASSWORD_REQUIREMENTS = exports.PASSWORD_PATTERNS = exports.AUTH_CONSTANTS = void 0;
const shared_1 = require("@zero/shared");
exports.AUTH_CONSTANTS = {
    // JWT Configuration
    JWT_ISSUER: 'zero-security',
    JWT_AUDIENCE: 'zero-app',
    ACCESS_TOKEN_EXPIRY: 15 * 60, // 15 minutos em segundos
    REFRESH_TOKEN_EXPIRY: 7 * 24 * 60 * 60, // 7 dias em segundos
    // Rate Limiting
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION: 30 * 60, // 30 minutos em segundos
    LOGIN_WINDOW_MS: 15 * 60 * 1000, // 15 minutos
    // MFA Configuration
    TOTP_DIGITS: 6,
    TOTP_PERIOD: 30, // segundos
    TOTP_WINDOW: 1, // aceita códigos anterior e próximo (janela de tolerância)
    BACKUP_CODES_COUNT: 10,
    BACKUP_CODES_LENGTH: 8,
    // Password Requirements (herdados do shared + adicionais)
    MIN_PASSWORD_LENGTH: shared_1.SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH: 128,
    // Session Configuration
    SESSION_PREFIX: 'sess_',
    REFRESH_TOKEN_PREFIX: 'rt_',
    MAX_SESSIONS_PER_USER: 10,
    TRUSTED_DEVICE_EXPIRY_DAYS: 30,
    // WebAuthn Configuration
    WEBAUTHN_CHALLENGE_TIMEOUT: 5 * 60 * 1000, // 5 minutos
    WEBAUTHN_RP_NAME: 'ZERO Security Center',
    WEBAUTHN_ATTESTATION_TIMEOUT: 60000, // 60 segundos
    // Audit
    AUDIT_RETENTION_DAYS: 365,
    // Error Messages (genéricos para não revelar informações)
    ERROR_MESSAGES: {
        INVALID_CREDENTIALS: 'Credenciais inválidas',
        USER_LOCKED: 'Conta temporariamente bloqueada. Tente novamente mais tarde.',
        MFA_REQUIRED: 'Autenticação de dois fatores necessária',
        MFA_INVALID_CODE: 'Código MFA inválido',
        SESSION_EXPIRED: 'Sessão expirada',
        RATE_LIMIT_EXCEEDED: 'Muitas tentativas. Tente novamente mais tarde.',
        INTERNAL_ERROR: 'Ocorreu um erro. Tente novamente.',
    },
    // Cookie Configuration
    COOKIE_CONFIG: {
        ACCESS_TOKEN_NAME: 'zero_at',
        REFRESH_TOKEN_NAME: 'zero_rt',
        SECURE: true,
        SAME_SITE: 'strict',
        HTTP_ONLY: true,
        PATH: '/',
    },
};
// Validação de senha adicional
exports.PASSWORD_PATTERNS = {
    LOWERCASE: /[a-z]/,
    UPPERCASE: /[A-Z]/,
    DIGIT: /\d/,
    SPECIAL: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/,
};
exports.PASSWORD_REQUIREMENTS = [
    { pattern: exports.PASSWORD_PATTERNS.LOWERCASE, message: 'letra minúscula' },
    { pattern: exports.PASSWORD_PATTERNS.UPPERCASE, message: 'letra maiúscula' },
    { pattern: exports.PASSWORD_PATTERNS.DIGIT, message: 'número' },
    { pattern: exports.PASSWORD_PATTERNS.SPECIAL, message: 'caractere especial' },
];
//# sourceMappingURL=constants.js.map
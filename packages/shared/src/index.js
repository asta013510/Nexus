"use strict";
/**
 * @zero/shared - Utilitários e tipos compartilhados
 *
 * Este pacote contém tipos, constantes e utilitários usados em todo o projeto ZERO.
 * Nenhuma lógica sensível de segurança deve residir aqui.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PermissionError = exports.NotFoundError = exports.AuthError = exports.SecurityError = exports.ValidationError = exports.BaseError = exports.PASSWORD_PATTERNS = exports.SECURITY_CONSTANTS = void 0;
exports.generateUUID = generateUUID;
exports.isValidUUID = isValidUUID;
exports.sanitizeFilename = sanitizeFilename;
exports.isMimeTypeAllowed = isMimeTypeAllowed;
exports.isExtensionBlocked = isExtensionBlocked;
// ============================================================================
// CONSTANTES E CONFIGURAÇÕES
// ============================================================================
exports.SECURITY_CONSTANTS = {
    // Argon2id parameters
    ARGON2_MEMORY_SIZE: 65536, // 64 MB
    ARGON2_TIME_COST: 3,
    ARGON2_PARALLELISM: 4,
    // Session management
    ACCESS_TOKEN_EXPIRY: 15 * 60, // 15 minutes in seconds
    REFRESH_TOKEN_EXPIRY: 7 * 24 * 60 * 60, // 7 days
    TRUSTED_DEVICE_EXPIRY: 30 * 24 * 60 * 60, // 30 days
    // Rate limiting
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION: 15 * 60, // 15 minutes
    MFA_MAX_ATTEMPTS: 3,
    BIOMETRIC_MAX_ATTEMPTS: 3,
    // Password requirements
    MIN_PASSWORD_LENGTH: 12,
    MAX_PASSWORD_LENGTH: 128,
    // File limits
    MAX_FILE_SIZE: 100 * 1024 * 1024, // 100 MB
    ALLOWED_MIME_TYPES: [
        'application/pdf',
        'image/jpeg',
        'image/png',
        'image/gif',
        'text/plain',
        'text/csv',
        'application/json',
        'application/zip',
        'application/x-zip-compressed',
    ],
    BLOCKED_EXTENSIONS: ['.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js', '.jar'],
    // TOTP
    TOTP_DIGITS: 6,
    TOTP_PERIOD: 30,
    TOTP_WINDOW: 1, // Allow 1 step before/after for clock skew
};
exports.PASSWORD_PATTERNS = {
    MIN_LENGTH: exports.SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH,
    MAX_LENGTH: exports.SECURITY_CONSTANTS.MAX_PASSWORD_LENGTH,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBER: true,
    REQUIRE_SPECIAL: true,
};
// ============================================================================
// CLASSES DE ERRO
// ============================================================================
class BaseError extends Error {
    code;
    details;
    constructor(code, message, details) {
        super(message);
        this.name = 'BaseError';
        this.code = code;
        if (details !== undefined) {
            this.details = details;
        }
        // Maintain proper stack trace in V8
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}
exports.BaseError = BaseError;
class ValidationError extends BaseError {
    constructor(message, details) {
        super('VALIDATION_ERROR', message, details);
        this.name = 'ValidationError';
    }
}
exports.ValidationError = ValidationError;
class SecurityError extends BaseError {
    constructor(message, details) {
        super('SECURITY_ERROR', message, details);
        this.name = 'SecurityError';
    }
}
exports.SecurityError = SecurityError;
class AuthError extends BaseError {
    constructor(message, details) {
        super('AUTH_ERROR', message, details);
        this.name = 'AuthError';
    }
}
exports.AuthError = AuthError;
class NotFoundError extends BaseError {
    constructor(message, details) {
        super('NOT_FOUND', message, details);
        this.name = 'NotFoundError';
    }
}
exports.NotFoundError = NotFoundError;
class PermissionError extends BaseError {
    constructor(message, details) {
        super('PERMISSION_DENIED', message, details);
        this.name = 'PermissionError';
    }
}
exports.PermissionError = PermissionError;
// ============================================================================
// UTILITÁRIOS
// ============================================================================
/**
 * Gera um UUID v4 seguro
 */
function generateUUID() {
    if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
        return crypto.randomUUID();
    }
    // Fallback para ambientes sem crypto.randomUUID
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
}
/**
 * Valida se uma string é um UUID válido
 */
function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}
/**
 * Sanitiza um nome de arquivo para uso seguro
 */
function sanitizeFilename(filename) {
    // Remove caracteres perigosos e normaliza
    return filename
        .normalize('NFC')
        .replace(/[/\\?%*:|"<>]/g, '_')
        .replace(/\.\./g, '_')
        .trim()
        .slice(0, 255);
}
/**
 * Verifica se um MIME type é permitido
 */
function isMimeTypeAllowed(mimeType) {
    return exports.SECURITY_CONSTANTS.ALLOWED_MIME_TYPES.includes(mimeType.toLowerCase());
}
/**
 * Verifica se uma extensão é bloqueada
 */
function isExtensionBlocked(extension) {
    return exports.SECURITY_CONSTANTS.BLOCKED_EXTENSIONS.includes(extension.toLowerCase());
}
exports.default = {
    generateUUID,
    isValidUUID,
    sanitizeFilename,
    isMimeTypeAllowed,
    isExtensionBlocked,
    SECURITY_CONSTANTS: exports.SECURITY_CONSTANTS,
};
//# sourceMappingURL=index.js.map
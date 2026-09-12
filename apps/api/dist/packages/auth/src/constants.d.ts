/**
 * Constantes de Autenticação
 *
 * Valores configuráveis para segurança e comportamento do sistema de auth
 */
export declare const AUTH_CONSTANTS: {
    readonly JWT_ISSUER: "zero-security";
    readonly JWT_AUDIENCE: "zero-app";
    readonly ACCESS_TOKEN_EXPIRY: number;
    readonly REFRESH_TOKEN_EXPIRY: number;
    readonly MAX_LOGIN_ATTEMPTS: 5;
    readonly LOCKOUT_DURATION: number;
    readonly LOGIN_WINDOW_MS: number;
    readonly TOTP_DIGITS: 6;
    readonly TOTP_PERIOD: 30;
    readonly TOTP_WINDOW: 1;
    readonly BACKUP_CODES_COUNT: 10;
    readonly BACKUP_CODES_LENGTH: 8;
    readonly RECOVERY_CODE_COUNT: 10;
    readonly MIN_PASSWORD_LENGTH: 12;
    readonly MAX_PASSWORD_LENGTH: 128;
    readonly SESSION_PREFIX: "sess_";
    readonly REFRESH_TOKEN_PREFIX: "rt_";
    readonly MAX_SESSIONS_PER_USER: 10;
    readonly TRUSTED_DEVICE_EXPIRY_DAYS: 30;
    readonly WEBAUTHN_CHALLENGE_TIMEOUT: number;
    readonly WEBAUTHN_RP_NAME: "ZERO Security Center";
    readonly WEBAUTHN_ATTESTATION_TIMEOUT: 60000;
    readonly AUDIT_RETENTION_DAYS: 365;
    readonly ERROR_MESSAGES: {
        readonly INVALID_CREDENTIALS: "Credenciais inválidas";
        readonly USER_LOCKED: "Conta temporariamente bloqueada. Tente novamente mais tarde.";
        readonly MFA_REQUIRED: "Autenticação de dois fatores necessária";
        readonly MFA_INVALID_CODE: "Código MFA inválido";
        readonly SESSION_EXPIRED: "Sessão expirada";
        readonly RATE_LIMIT_EXCEEDED: "Muitas tentativas. Tente novamente mais tarde.";
        readonly INTERNAL_ERROR: "Ocorreu um erro. Tente novamente.";
    };
    readonly COOKIE_CONFIG: {
        readonly ACCESS_TOKEN_NAME: "zero_at";
        readonly REFRESH_TOKEN_NAME: "zero_rt";
        readonly SECURE: true;
        readonly SAME_SITE: "strict";
        readonly HTTP_ONLY: true;
        readonly PATH: "/";
    };
};
export declare const PASSWORD_PATTERNS: {
    readonly LOWERCASE: RegExp;
    readonly UPPERCASE: RegExp;
    readonly DIGIT: RegExp;
    readonly SPECIAL: RegExp;
};
export declare const PASSWORD_REQUIREMENTS: readonly [{
    readonly pattern: RegExp;
    readonly message: "letra minúscula";
}, {
    readonly pattern: RegExp;
    readonly message: "letra maiúscula";
}, {
    readonly pattern: RegExp;
    readonly message: "número";
}, {
    readonly pattern: RegExp;
    readonly message: "caractere especial";
}];
//# sourceMappingURL=constants.d.ts.map
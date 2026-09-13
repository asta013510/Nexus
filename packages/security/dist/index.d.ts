/**
 * @zero/security - Módulo de Segurança
 *
 * SECURITY: Validações, rate limiting e verificações de segurança
 */
/**
 * Valida email com verificação estrita
 */
export declare function isValidEmail(email: string): boolean;
/**
 * Valida força da senha
 * SECURITY: Requisitos mínimos conforme políticas do ZERO
 */
export declare function isPasswordStrong(password: string): {
    valid: boolean;
    errors: string[];
};
/**
 * Gera chave única para rate limiting por IP + ação
 */
export declare function getRateLimitKey(ip: string, action: string): string;
/**
 * Configuração padrão de rate limiting para login
 */
export declare const LOGIN_RATE_LIMIT: {
    windowMs: number;
    max: 5;
    message: string;
};
/**
 * Configuração de rate limiting para MFA
 */
export declare const MFA_RATE_LIMIT: {
    windowMs: number;
    max: 3;
    message: string;
};
/**
 * Configuração de rate limiting para biometria
 */
export declare const BIOMETRIC_RATE_LIMIT: {
    windowMs: number;
    max: 3;
    message: string;
};
/**
 * Sanitiza string para uso seguro em logs/outputs
 * SECURITY: Remove possíveis injection vectors
 */
export declare function sanitizeInput(input: string): string;
/**
 * Sanitiza nome de arquivo
 */
export declare function sanitizeFilename(filename: string): string;
/**
 * Extrai IP real de request (considerando proxies)
 */
export declare function extractIP(headers: Record<string, string | undefined>): string;
/**
 * Extrai informações básicas do User-Agent
 * SECURITY: Não logar UA completo (pode conter dados sensíveis)
 */
export declare function parseUserAgent(userAgent?: string): {
    browser: string;
    os: string;
    deviceType: string;
};
declare const _default: {
    isValidEmail: typeof isValidEmail;
    isPasswordStrong: typeof isPasswordStrong;
    getRateLimitKey: typeof getRateLimitKey;
    sanitizeInput: typeof sanitizeInput;
    sanitizeFilename: typeof sanitizeFilename;
    extractIP: typeof extractIP;
    parseUserAgent: typeof parseUserAgent;
    LOGIN_RATE_LIMIT: {
        windowMs: number;
        max: 5;
        message: string;
    };
    MFA_RATE_LIMIT: {
        windowMs: number;
        max: 3;
        message: string;
    };
    BIOMETRIC_RATE_LIMIT: {
        windowMs: number;
        max: 3;
        message: string;
    };
};
export default _default;
//# sourceMappingURL=index.d.ts.map
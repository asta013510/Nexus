/**
 * @zero/security - Módulo de Segurança
 *
 * SECURITY: Validações, rate limiting e verificações de segurança
 */
import validator from 'validator';
import { SECURITY_CONSTANTS } from '@zero/shared';
// ============================================================================
// VALIDAÇÃO DE EMAIL
// ============================================================================
/**
 * Valida email com verificação estrita
 */
export function isValidEmail(email) {
    if (!email || typeof email !== 'string') {
        return false;
    }
    // Usar validator.isEmail com opções estritas
    return validator.isEmail(email, {
        allow_display_name: false,
        allow_utf8_local_part: false,
        require_tld: true,
        ignore_max_length: false,
    });
}
// ============================================================================
// VALIDAÇÃO DE SENHA
// ============================================================================
/**
 * Valida força da senha
 * SECURITY: Requisitos mínimos conforme políticas do ZERO
 */
export function isPasswordStrong(password) {
    const errors = [];
    if (!password) {
        return { valid: false, errors: ['Senha é obrigatória'] };
    }
    // Comprimento mínimo
    if (password.length < SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH) {
        errors.push(`Senha deve ter pelo menos ${SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH} caracteres`);
    }
    // Comprimento máximo
    if (password.length > SECURITY_CONSTANTS.MAX_PASSWORD_LENGTH) {
        errors.push(`Senha deve ter no máximo ${SECURITY_CONSTANTS.MAX_PASSWORD_LENGTH} caracteres`);
    }
    // Caracteres especiais
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Senha deve conter pelo menos um caractere especial');
    }
    // Números
    if (!/\d/.test(password)) {
        errors.push('Senha deve conter pelo menos um número');
    }
    // Letras maiúsculas e minúsculas
    if (!/[a-z]/.test(password) || !/[A-Z]/.test(password)) {
        errors.push('Senha deve conter letras maiúsculas e minúsculas');
    }
    // Verificar senhas comuns (lista básica)
    const commonPasswords = [
        'password',
        '123456',
        '12345678',
        'qwerty',
        'abc123',
        'monkey',
        'master',
        'dragon',
        'letmein',
        'login',
    ];
    if (commonPasswords.some((p) => password.toLowerCase().includes(p))) {
        errors.push('Senha muito comum. Escolha uma senha mais única.');
    }
    return {
        valid: errors.length === 0,
        errors,
    };
}
// ============================================================================
// RATE LIMITING HELPERS
// ============================================================================
/**
 * Gera chave única para rate limiting por IP + ação
 */
export function getRateLimitKey(ip, action) {
    return `ratelimit:${action}:${ip}`;
}
/**
 * Configuração padrão de rate limiting para login
 */
export const LOGIN_RATE_LIMIT = {
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: SECURITY_CONSTANTS.MAX_LOGIN_ATTEMPTS,
    message: 'Muitas tentativas de login. Tente novamente em 15 minutos.',
};
/**
 * Configuração de rate limiting para MFA
 */
export const MFA_RATE_LIMIT = {
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: SECURITY_CONSTANTS.MFA_MAX_ATTEMPTS,
    message: 'Muitas tentativas de MFA. Tente novamente em 15 minutos.',
};
/**
 * Configuração de rate limiting para biometria
 */
export const BIOMETRIC_RATE_LIMIT = {
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: SECURITY_CONSTANTS.BIOMETRIC_MAX_ATTEMPTS,
    message: 'Muitas tentativas de reconhecimento facial. Use outro método de autenticação.',
};
// ============================================================================
// SANITIZAÇÃO
// ============================================================================
/**
 * Sanitiza string para uso seguro em logs/outputs
 * SECURITY: Remove possíveis injection vectors
 */
export function sanitizeInput(input) {
    if (!input) {
        return '';
    }
    // Remover null bytes
    let sanitized = input.replace(/\0/g, '');
    // Limitar tamanho máximo
    if (sanitized.length > 10000) {
        sanitized = sanitized.slice(0, 10000);
    }
    return sanitized.trim();
}
/**
 * Sanitiza nome de arquivo
 */
export function sanitizeFilename(filename) {
    return filename
        .normalize('NFC')
        .replace(/[/\\?%*:|"<>]/g, '_')
        .replace(/\.\./g, '_')
        .replace(/\s+/g, '_')
        .trim()
        .slice(0, 255);
}
// ============================================================================
// IP & USER AGENT
// ============================================================================
/**
 * Extrai IP real de request (considerando proxies)
 */
export function extractIP(headers) {
    // Ordem de verificação para IPs atrás de proxy
    const forwarded = headers['x-forwarded-for'];
    if (forwarded) {
        // Pegar primeiro IP (client original)
        return forwarded.split(',')[0].trim();
    }
    const realIP = headers['x-real-ip'];
    if (realIP) {
        return realIP.trim();
    }
    return headers['x-client-ip'] || 'unknown';
}
/**
 * Extrai informações básicas do User-Agent
 * SECURITY: Não logar UA completo (pode conter dados sensíveis)
 */
export function parseUserAgent(userAgent) {
    if (!userAgent) {
        return { browser: 'Unknown', os: 'Unknown', deviceType: 'unknown' };
    }
    const ua = userAgent.toLowerCase();
    let browser = 'Unknown';
    if (ua.includes('firefox'))
        browser = 'Firefox';
    else if (ua.includes('chrome'))
        browser = 'Chrome';
    else if (ua.includes('safari'))
        browser = 'Safari';
    else if (ua.includes('edge'))
        browser = 'Edge';
    else if (ua.includes('opera'))
        browser = 'Opera';
    let os = 'Unknown';
    if (ua.includes('windows'))
        os = 'Windows';
    else if (ua.includes('mac'))
        os = 'macOS';
    else if (ua.includes('linux'))
        os = 'Linux';
    else if (ua.includes('android'))
        os = 'Android';
    else if (ua.includes('ios'))
        os = 'iOS';
    let deviceType = 'desktop';
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
        deviceType = 'mobile';
    }
    else if (ua.includes('tablet') || ua.includes('ipad')) {
        deviceType = 'tablet';
    }
    return { browser, os, deviceType };
}
// ============================================================================
// EXPORTS
// ============================================================================
export default {
    isValidEmail,
    isPasswordStrong,
    getRateLimitKey,
    sanitizeInput,
    sanitizeFilename,
    extractIP,
    parseUserAgent,
    LOGIN_RATE_LIMIT,
    MFA_RATE_LIMIT,
    BIOMETRIC_RATE_LIMIT,
};
//# sourceMappingURL=index.js.map
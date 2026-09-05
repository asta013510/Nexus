"use strict";
/**
 * Utils de Validação para Autenticação
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.mfaVerificationSchema = exports.loginSchema = exports.registerSchema = void 0;
exports.validateEmail = validateEmail;
exports.validatePassword = validatePassword;
exports.sanitizeInput = sanitizeInput;
exports.normalizeEmail = normalizeEmail;
const zod_1 = require("zod");
const shared_1 = require("@zero/shared");
const constants_1 = require("../constants");
/**
 * Valida formato de email
 */
function validateEmail(email) {
    if (!email || typeof email !== 'string') {
        return {
            valid: false,
            error: { code: 'EMAIL_INVALID', message: 'Email inválido' },
        };
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return {
            valid: false,
            error: { code: 'EMAIL_INVALID', message: 'Email inválido' },
        };
    }
    if (email.length > 254) {
        return {
            valid: false,
            error: { code: 'EMAIL_INVALID', message: 'Email muito longo' },
        };
    }
    return { valid: true };
}
/**
 * Valida força da senha conforme políticas de segurança
 *
 * Requisitos:
 * - Mínimo 12 caracteres (OWASP recommendation)
 * - Pelo menos uma letra maiúscula
 * - Pelo menos uma letra minúscula
 * - Pelo menos um número
 * - Pelo menos um caractere especial
 * - Não conter padrões comuns
 */
function validatePassword(password) {
    if (!password || typeof password !== 'string') {
        return {
            valid: false,
            error: { code: 'PASSWORD_WEAK', message: 'Senha inválida' },
        };
    }
    const requirements = [];
    const failedRequirements = [];
    // Verificar comprimento mínimo
    if (password.length < shared_1.SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH) {
        failedRequirements.push(`mínimo ${shared_1.SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH} caracteres`);
    }
    else {
        requirements.push(`mínimo ${shared_1.SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH} caracteres ✓`);
    }
    // Verificar comprimento máximo
    if (password.length > constants_1.AUTH_CONSTANTS.MAX_PASSWORD_LENGTH) {
        return {
            valid: false,
            error: { code: 'PASSWORD_WEAK', message: 'Senha muito longa' },
        };
    }
    // Verificar requisitos de complexidade
    for (const req of constants_1.PASSWORD_REQUIREMENTS) {
        if (!req.pattern.test(password)) {
            failedRequirements.push(req.message);
        }
        else {
            requirements.push(`${req.message} ✓`);
        }
    }
    // Verificar senhas comuns/padrões
    const commonPatterns = [
        /password/i,
        /123456/,
        /qwerty/,
        /abc123/,
        /letmein/,
        /welcome/,
        /admin123/,
        /zero123/,
    ];
    for (const pattern of commonPatterns) {
        if (pattern.test(password)) {
            return {
                valid: false,
                error: {
                    code: 'PASSWORD_WEAK',
                    message: 'Senha contém padrão comum. Escolha uma senha mais única.'
                },
            };
        }
    }
    // Verificar sequências óbvias
    const sequences = [
        '0123456789',
        'abcdefghijklmnopqrstuvwxyz',
        'zyxwvutsrqponmlkjihgfedcba',
        '9876543210',
    ];
    for (const seq of sequences) {
        for (let i = 0; i <= seq.length - 4; i++) {
            if (password.toLowerCase().includes(seq.substring(i, i + 4))) {
                return {
                    valid: false,
                    error: {
                        code: 'PASSWORD_WEAK',
                        message: 'Senha contém sequência previsível'
                    },
                };
            }
        }
    }
    if (failedRequirements.length > 0) {
        return {
            valid: false,
            error: {
                code: 'PASSWORD_WEAK',
                message: `Senha não atende requisitos: ${failedRequirements.join(', ')}`
            },
            requirements,
        };
    }
    return { valid: true, requirements };
}
/**
 * Schema Zod para registro de usuário
 */
exports.registerSchema = zod_1.z.object({
    email: zod_1.z.string().email('Email inválido').max(254),
    password: zod_1.z.string()
        .min(shared_1.SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH, `Mínimo ${shared_1.SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH} caracteres`)
        .max(constants_1.AUTH_CONSTANTS.MAX_PASSWORD_LENGTH, 'Senha muito longa'),
    displayName: zod_1.z.string().min(1).max(100).optional(),
    recoveryEmail: zod_1.z.string().email().max(254).optional(),
});
/**
 * Schema Zod para login
 */
exports.loginSchema = zod_1.z.object({
    email: zod_1.z.string().email('Email inválido'),
    password: zod_1.z.string().min(1),
    mfaCode: zod_1.z.string().length(6).regex(/^\d+$/).optional(),
    deviceId: zod_1.z.string().uuid().optional(),
    rememberDevice: zod_1.z.boolean().optional().default(false),
});
/**
 * Schema Zod para verificação MFA
 */
exports.mfaVerificationSchema = zod_1.z.object({
    userId: zod_1.z.string().uuid(),
    code: zod_1.z.string().length(6).regex(/^\d+$/, 'Código deve ter 6 dígitos'),
    type: zod_1.z.enum(['totp', 'recovery']),
});
/**
 * Sanitiza input de texto para prevenir injection
 */
function sanitizeInput(input) {
    return input
        .replace(/[<>]/g, '') // Remove tags HTML
        .replace(/[\u0000-\u001F\u007F-\u009F]/g, '') // Remove controle characters
        .trim();
}
/**
 * Normaliza email para lowercase e trim
 */
function normalizeEmail(email) {
    return email.toLowerCase().trim();
}
//# sourceMappingURL=validation.js.map
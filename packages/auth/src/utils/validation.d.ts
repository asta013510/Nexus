/**
 * Utils de Validação para Autenticação
 */
import { z } from 'zod';
import type { AuthError } from '../types';
/**
 * Valida formato de email
 */
export declare function validateEmail(email: string): {
    valid: boolean;
    error?: AuthError;
};
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
export declare function validatePassword(password: string): {
    valid: boolean;
    error?: AuthError;
    requirements?: string[];
};
/**
 * Schema Zod para registro de usuário
 */
export declare const registerSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
    displayName: z.ZodOptional<z.ZodString>;
    recoveryEmail: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
    displayName?: string | undefined;
    recoveryEmail?: string | undefined;
}, {
    email: string;
    password: string;
    displayName?: string | undefined;
    recoveryEmail?: string | undefined;
}>;
/**
 * Schema Zod para login
 */
export declare const loginSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
    mfaCode: z.ZodOptional<z.ZodString>;
    deviceId: z.ZodOptional<z.ZodString>;
    rememberDevice: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
    rememberDevice: boolean;
    deviceId?: string | undefined;
    mfaCode?: string | undefined;
}, {
    email: string;
    password: string;
    deviceId?: string | undefined;
    mfaCode?: string | undefined;
    rememberDevice?: boolean | undefined;
}>;
/**
 * Schema Zod para verificação MFA
 */
export declare const mfaVerificationSchema: z.ZodObject<{
    userId: z.ZodString;
    code: z.ZodString;
    type: z.ZodEnum<["totp", "recovery"]>;
}, "strip", z.ZodTypeAny, {
    userId: string;
    type: "totp" | "recovery";
    code: string;
}, {
    userId: string;
    type: "totp" | "recovery";
    code: string;
}>;
/**
 * Sanitiza input de texto para prevenir injection
 */
export declare function sanitizeInput(input: string): string;
/**
 * Normaliza email para lowercase e trim
 */
export declare function normalizeEmail(email: string): string;
//# sourceMappingURL=validation.d.ts.map
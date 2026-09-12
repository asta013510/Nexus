/**
 * Utils de Validação para Autenticação
 */

import { z } from 'zod';
import { SECURITY_CONSTANTS, PASSWORD_PATTERNS } from '@zero/shared';
import { AUTH_CONSTANTS, PASSWORD_REQUIREMENTS } from '../constants';
import type { AuthError } from '../types';

/**
 * Valida formato de email
 */
export function validateEmail(email: string): { valid: boolean; error?: AuthError } {
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
export function validatePassword(password: string): { 
  valid: boolean; 
  error?: AuthError;
  requirements?: string[];
} {
  if (!password || typeof password !== 'string') {
    return {
      valid: false,
      error: { code: 'PASSWORD_WEAK', message: 'Senha inválida' },
    };
  }

  const requirements: string[] = [];
  const failedRequirements: string[] = [];

  // Verificar comprimento mínimo
  if (password.length < SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH) {
    failedRequirements.push(`mínimo ${SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH} caracteres`);
  } else {
    requirements.push(`mínimo ${SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH} caracteres ✓`);
  }

  // Verificar comprimento máximo
  if (password.length > AUTH_CONSTANTS.MAX_PASSWORD_LENGTH) {
    return {
      valid: false,
      error: { code: 'PASSWORD_WEAK', message: 'Senha muito longa' },
    };
  }

  // Verificar requisitos de complexidade
  for (const req of PASSWORD_REQUIREMENTS) {
    if (!req.pattern.test(password)) {
      failedRequirements.push(req.message);
    } else {
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
export const registerSchema = z.object({
  email: z.string().email('Email inválido').max(254),
  password: z.string()
    .min(SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH, `Mínimo ${SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH} caracteres`)
    .max(AUTH_CONSTANTS.MAX_PASSWORD_LENGTH, 'Senha muito longa'),
  displayName: z.string().min(1).max(100).optional(),
  recoveryEmail: z.string().email().max(254).optional(),
});

/**
 * Schema Zod para login
 */
export const loginSchema = z.object({
  email: z.string().email('Email inválido'),
  password: z.string().min(1),
  mfaCode: z.string().length(6).regex(/^\d+$/).optional(),
  deviceId: z.string().uuid().optional(),
  rememberDevice: z.boolean().optional().default(false),
});

/**
 * Schema Zod para verificação MFA
 */
export const mfaVerificationSchema = z.object({
  userId: z.string().uuid(),
  code: z.string().length(6).regex(/^\d+$/, 'Código deve ter 6 dígitos'),
  type: z.enum(['totp', 'recovery']),
});

/**
 * Sanitiza input de texto para prevenir injection
 */
export function sanitizeInput(input: string): string {
  return input
    .replace(/[<>]/g, '') // Remove tags HTML
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, '') // Remove controle characters
    .trim();
}

/**
 * Normaliza email para lowercase e trim
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

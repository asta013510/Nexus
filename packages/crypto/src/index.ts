/**
 * @zero/crypto - Módulo de Criptografia
 * 
 * SECURITY: Wrapper seguro para operações criptográficas
 * NUNCA implementar algoritmos próprios - usar bibliotecas auditadas
 */

import argon2 from 'argon2';
import { generateUUID } from '@zero/shared';

// ============================================================================
// CONSTANTES DE SEGURANÇA (Argon2id)
// ============================================================================

export const ARGON2_CONFIG = {
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
} as const;

// ============================================================================
// PASSWORD HASHING (Argon2id)
// ============================================================================

/**
 * Gera salt seguro para password hashing
 */
export function generateSalt(): string {
  return generateUUID().replace(/-/g, '');
}

/**
 * Hash de senha usando Argon2id
 * SECURITY: Parâmetros hardcoded conforme OWASP recommendations
 */
export async function hashPassword(password: string, salt?: string): Promise<string> {
  if (!password || password.length < 12) {
    throw new Error('Senha muito curta. Mínimo 12 caracteres.');
  }

  const actualSalt = salt || generateSalt();
  
  const hash = await argon2.hash(password, {
    type: argon2.argon2id,
    ...ARGON2_CONFIG,
    salt: Buffer.from(actualSalt),
  });

  return hash;
}

/**
 * Verifica se senha corresponde ao hash
 * SECURITY: Constant-time comparison (feito pelo argon2)
 */
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch (error) {
    // Em caso de erro, retornar false (não vazar informações)
    console.error('Erro ao verificar password:', error);
    return false;
  }
}

/**
 * Verifica se hash precisa ser re-hash (para upgrade de parâmetros)
 */
export function needsRehash(hash: string): boolean {
  return argon2.verify(hash, 'dummy').catch(() => true);
}

// ============================================================================
// UTILITÁRIOS CRIPTOGRÁFICOS
// ============================================================================

/**
 * Gera token seguro aleatório
 */
export function generateSecureToken(length: number = 32): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Gera código numérico seguro (para TOTP/recovery codes)
 */
export function generateNumericCode(digits: number = 6): string {
  const min = Math.pow(10, digits - 1);
  const max = Math.pow(10, digits) - 1;
  const number = crypto.getRandomValues(new Uint32Array(1))[0] % (max - min + 1) + min;
  return number.toString().padStart(digits, '0');
}

/**
 * Hash seguro para dados não-sensíveis (ex: identificar email sem expor)
 */
export async function hashIdentifier(identifier: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(identifier + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// ENCRYPTION (AES-GCM via Web Crypto API)
// ============================================================================

/**
 * Deriva chave de encryption a partir de master key
 */
export async function deriveKey(masterKey: string, salt: string, purpose: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(masterKey),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode(salt + purpose),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encripta dados usando AES-256-GCM
 */
export async function encrypt(data: string, key: CryptoKey): Promise<{
  ciphertext: string;
  iv: string;
  tag: string;
}> {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(data)
  );

  const encryptedBytes = new Uint8Array(encrypted);
  const ciphertext = encryptedBytes.slice(0, -16);
  const tag = encryptedBytes.slice(-16);

  return {
    ciphertext: Buffer.from(ciphertext).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    tag: Buffer.from(tag).toString('base64'),
  };
}

/**
 * Decripta dados usando AES-256-GCM
 */
export async function decrypt(
  ciphertext: string,
  iv: string,
  tag: string,
  key: CryptoKey
): Promise<string> {
  const decoder = new TextDecoder();
  const ivBytes = Buffer.from(iv, 'base64');
  const ciphertextBytes = Buffer.from(ciphertext, 'base64');
  const tagBytes = Buffer.from(tag, 'base64');

  const encryptedData = new Uint8Array(ciphertextBytes.length + tagBytes.length);
  encryptedData.set(ciphertextBytes);
  encryptedData.set(tagBytes, ciphertextBytes.length);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes },
    key,
    encryptedData
  );

  return decoder.decode(decrypted);
}

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  hashPassword,
  verifyPassword,
  needsRehash,
  generateSalt,
  generateSecureToken,
  generateNumericCode,
  hashIdentifier,
  deriveKey,
  encrypt,
  decrypt,
  ARGON2_CONFIG,
};

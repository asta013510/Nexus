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
export async function needsRehash(hash: string): Promise<boolean> {
  try {
    await argon2.verify(hash, 'dummy');
    return false;
  } catch {
    return true;
  }
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
 * Hash SHA-256 seguro para dados não-sensíveis
 */
export async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Gera secret TOTP e retorna em formato base32
 */
export function generateTOTPSecret(): { secret: string; algorithm: string; digits: number; period: number } {
  // Gerar 20 bytes aleatórios para secret base32
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let secret = '';
  
  for (let i = 0; i < bytes.length; i += 5) {
    const chunk = bytes.subarray(i, Math.min(i + 5, bytes.length));
    // Converter para base32 simplificado
    for (let j = 0; j < chunk.length; j++) {
      const val = chunk[j];
      secret += base32Chars.charAt((val >> 3) & 0x1F);
      if (j < chunk.length - 1 || (i + 5) < bytes.length) {
        secret += base32Chars.charAt(((val & 0x07) << 2) | ((chunk[j + 1] ?? 0) >> 6));
      }
    }
  }
  
  return {
    secret: secret.slice(0, 32), // 32 caracteres
    algorithm: 'SHA-256',
    digits: 6,
    period: 30,
  };
}

/**
 * Gera código TOTP para um tempo específico (usado internamente)
 */
export async function generateTOTP(secret: string, timeStep?: number): Promise<string> {
  const now = timeStep || Math.floor(Date.now() / 1000);
  const period = 30;
  
  // Decodificar secret base32
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const secretBytes = new Uint8Array(secret.length);
  for (let i = 0; i < secret.length; i++) {
    const idx = base32Chars.indexOf(secret[i].toUpperCase());
    if (idx === -1) throw new Error('Invalid base32 secret');
    secretBytes[i] = idx;
  }
  
  return generateTOTPForTime(secretBytes, now, period);
}

/**
 * Verifica código TOTP
 * SECURITY: Constant-time comparison
 */
export async function verifyTOTP(secret: string, code: string, window: number = 1): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  const period = 30;
  
  // Decodificar secret base32
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const secretBytes = new Uint8Array(secret.length);
  for (let i = 0; i < secret.length; i++) {
    const idx = base32Chars.indexOf(secret[i].toUpperCase());
    if (idx === -1) throw new Error('Invalid base32 secret');
    secretBytes[i] = idx;
  }
  
  // Verificar em uma janela de tempo (para compensar clock skew)
  for (let i = -window; i <= window; i++) {
    const timeStep = now + (i * period);
    const expectedCode = await generateTOTPForTime(secretBytes, timeStep, period);
    
    // Constant-time comparison
    if (timingSafeCompare(code.padStart(6, '0'), expectedCode)) {
      return true;
    }
  }
  
  return false;
}

async function generateTOTPForTime(secret: Uint8Array, timeStep: number, period: number): Promise<string> {
  const counterValue = Math.floor(timeStep / period);
  const counterBytes = new Uint8Array(8);
  
  // Big-endian counter
  let counter = counterValue;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = counter & 0xff;
    counter >>= 8;
  }
  
  // HMAC-SHA256
  const key = await crypto.subtle.importKey(
    'raw' as const,
    secret.buffer as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, counterBytes);
  const sigBytes = new Uint8Array(signature);
  
  // Dynamic truncation (RFC 4226)
  const offset = sigBytes[sigBytes.length - 1] & 0x0f;
  const binary = ((sigBytes[offset] & 0x7f) << 24) |
                 ((sigBytes[offset + 1] & 0xff) << 16) |
                 ((sigBytes[offset + 2] & 0xff) << 8) |
                 (sigBytes[offset + 3] & 0xff);
  
  const otp = (binary % 1000000).toString().padStart(6, '0');
  return otp;
}

/**
 * Gera recovery codes
 */
export function generateRecoveryCodes(count: number = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    // Formato: XXXX-YYYY-ZZZZ (12 dígitos)
    const part1 = generateNumericCode(4);
    const part2 = generateNumericCode(4);
    const part3 = generateNumericCode(4);
    codes.push(`${part1}-${part2}-${part3}`);
  }
  return codes;
}

/**
 * Comparison constante para prevenir timing attacks
 */
export function timingSafeCompare(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  
  if (aBytes.length !== bBytes.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i] ^ bBytes[i];
  }
  
  return result === 0;
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
export async function deriveKey(
  masterKey: string,
  salt: string,
  purpose: string
): Promise<CryptoKey> {
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
export async function encrypt(
  data: string,
  key: CryptoKey
): Promise<{
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

// JWT exports
export { generateAccessToken, generateRefreshToken, verifyJWT, decodeJWT } from './jwt.js';
export type { JWTPayload, RefreshTokenPayload } from './jwt.js';

// ============================================================================
// FILE ENCRYPTION (AES-256-GCM for Buffer data)
// ============================================================================

/**
 * Gera bytes aleatórios seguros para chaves de encryption
 */
export function randomBytes(length: number): Buffer {
  const crypto = require('crypto');
  return crypto.randomBytes(length);
}

/**
 * Encripta um Buffer (arquivo) usando AES-256-GCM
 * Retorna objeto com dados encriptados e metadados necessários para decrypt
 */
export async function encryptFile(
  data: Buffer,
  key: Buffer
): Promise<{
  encryptedData: Buffer;
  iv: Buffer;
  authTag: Buffer;
}> {
  const crypto = require('crypto');
  
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  const encrypted = Buffer.concat([
    cipher.update(data),
    cipher.final()
  ]);
  
  const authTag = cipher.getAuthTag();
  
  return {
    encryptedData: encrypted,
    iv: iv,
    authTag: authTag,
  };
}

/**
 * Decripta um Buffer (arquivo) usando AES-256-GCM
 */
export async function decryptFile(
  encryptedData: Buffer,
  iv: Buffer,
  authTag: Buffer,
  key: Buffer
): Promise<Buffer> {
  const crypto = require('crypto');
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  
  const decrypted = Buffer.concat([
    decipher.update(encryptedData),
    decipher.final()
  ]);
  
  return decrypted;
}

// Wrapper simplificado para encryptFile quando key é Buffer
export async function encryptFileWithKey(
  data: Buffer,
  key: Buffer
): Promise<{
  encryptedData: Buffer;
  iv: Buffer;
  authTag: Buffer;
}> {
  return encryptFile(data, key);
}

// Wrapper simplificado para decryptFile quando todos os params são Buffer
export async function decryptFileWithKey(
  encryptedData: Buffer,
  iv: Buffer,
  authTag: Buffer,
  key: Buffer
): Promise<Buffer> {
  return decryptFile(encryptedData, iv, authTag, key);
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
  randomBytes,
  encryptFile,
  decryptFile,
  encryptFileWithKey,
  decryptFileWithKey,
  ARGON2_CONFIG,
  sha256,
  generateTOTPSecret,
  generateTOTP,
  verifyTOTP,
  generateRecoveryCodes,
  timingSafeCompare,
};

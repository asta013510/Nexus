/**
 * @zero/crypto - Operações Criptográficas Seguras
 * 
 * ESTE MÓDULO FORNECE PRIMITIVAS CRIPTOGRÁFICAS AUDITADAS.
 * NUNCA implemente algoritmos criptográficos próprios.
 * SEMPRE use bibliotecas padrão e auditadas.
 * 
 * Segurança primeiro:
 * - Usar apenas algoritmos aprovados (AES-256-GCM, SHA-256, Argon2id)
 * - Nunca reutilizar nonces/IVs
 * - Validar autenticação antes de descriptografar
 * - Limpar memória de dados sensíveis quando possível
 */

import { sha256, hmac } from '@noble/hashes/sha256';
import { argon2id } from '@noble/hashes/argon2';
import { randomBytes } from '@noble/hashes/utils';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

// ============================================================================
// CONSTANTES E TIPOS
// ============================================================================

export const CRYPTO_CONSTANTS = {
  // AES-GCM
  AES_KEY_LENGTH: 256,
  AES_NONCE_LENGTH: 12,
  AES_TAG_LENGTH: 16,
  
  // Argon2id
  ARGON2_MEMORY_SIZE: 65536, // 64 MB
  ARGON2_TIME_COST: 3,
  ARGON2_PARALLELISM: 4,
  ARGON2_HASH_LENGTH: 32,
  
  // Hash
  SHA256_LENGTH: 32,
  
  // HMAC
  HMAC_KEY_LENGTH: 32,
  
  // Key derivation
  PBKDF_SALT_LENGTH: 32,
  
  // Encryption limits
  MAX_ENCRYPT_SIZE: 1024 * 1024 * 1024, // 1 GB
} as const;

export interface EncryptedData {
  ciphertext: string; // Base64
  iv: string; // Base64
  tag: string; // Base64 (authentication tag)
  algorithm: string;
}

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

// ============================================================================
// UTILITÁRIOS DE CODIFICAÇÃO
// ============================================================================

/**
 * Converte Uint8Array para base64
 */
export function toBase64(data: Uint8Array): string {
  return naclUtil.encodeBase64(data);
}

/**
 * Converte base64 para Uint8Array
 */
export function fromBase64(base64: string): Uint8Array {
  return naclUtil.decodeBase64(base64);
}

/**
 * Converte string para Uint8Array
 */
export function toBytes(str: string): Uint8Array {
  return naclUtil.decodeUTF8(str);
}

/**
 * Converte Uint8Array para string
 */
export function toString(bytes: Uint8Array): string {
  return naclUtil.encodeUTF8(bytes);
}

/**
 * Gera bytes aleatórios seguros para uso criptográfico
 */
export function generateRandomBytes(length: number): Uint8Array {
  if (length <= 0 || length > 1024) {
    throw new Error('Invalid random bytes length');
  }
  return randomBytes(length);
}

// ============================================================================
// HASHING
// ============================================================================

/**
 * Calcula hash SHA-256 de dados
 * @param data - Dados para hashear (string ou Uint8Array)
 * @returns Hash em hex
 */
export function sha256Hash(data: string | Uint8Array): string {
  const bytes = typeof data === 'string' ? toBytes(data) : data;
  const hash = sha256(bytes);
  return Array.from(hash)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Calcula hash SHA-256 como Uint8Array
 */
export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * Calcula HMAC-SHA256
 * @param key - Chave secreta
 * @param data - Dados para autenticar
 * @returns HMAC em hex
 */
export function hmacSha256(key: Uint8Array, data: Uint8Array): string {
  const mac = hmac(key, data);
  return Array.from(mac)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ============================================================================
// DERIVAÇÃO DE CHAVE (Argon2id)
// ============================================================================

/**
 * Deriva uma chave usando Argon2id
 * 
 * Argon2id é o algoritmo recomendado para hashing de senhas (OWASP, PHC).
 * Resistente a GPU, ASIC e side-channel attacks.
 * 
 * @param password - Senha do usuário
 * @param salt - Salt aleatório (mínimo 32 bytes)
 * @param options - Opções de Argon2
 * @returns Chave derivada em hex
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  options: {
    memorySize?: number;
    timeCost?: number;
    parallelism?: number;
    hashLength?: number;
  } = {}
): Promise<string> {
  const {
    memorySize = CRYPTO_CONSTANTS.ARGON2_MEMORY_SIZE,
    timeCost = CRYPTO_CONSTANTS.ARGON2_TIME_COST,
    parallelism = CRYPTO_CONSTANTS.ARGON2_PARALLELISM,
    hashLength = CRYPTO_CONSTANTS.ARGON2_HASH_LENGTH,
  } = options;

  if (salt.length < 16) {
    throw new Error('Salt must be at least 16 bytes');
  }

  const passwordBytes = toBytes(password);
  
  const hash = await argon2id(passwordBytes, salt, {
    m: memorySize,
    t: timeCost,
    p: parallelism,
    dkLen: hashLength,
  });

  // Limpar senha da memória (best effort em JS)
  passwordBytes.fill(0);

  return toBase64(hash);
}

/**
 * Gera um salt seguro para derivação de chave
 */
export function generateSalt(length: number = CRYPTO_CONSTANTS.PBKDF_SALT_LENGTH): Uint8Array {
  return generateRandomBytes(length);
}

/**
 * Verifica se uma senha corresponde a um hash Argon2id
 * @param password - Senha para verificar
 * @param storedHash - Hash armazenado (base64)
 * @param salt - Salt usado (base64 ou Uint8Array)
 */
export async function verifyPassword(
  password: string,
  storedHash: string,
  salt: string | Uint8Array
): Promise<boolean> {
  try {
    const saltBytes = typeof salt === 'string' ? fromBase64(salt) : salt;
    const computedHash = await deriveKey(password, saltBytes);
    
    // Comparação constante para prevenir timing attacks
    return secureCompare(computedHash, storedHash);
  } catch {
    return false;
  }
}

// ============================================================================
// COMPARAÇÃO SEGURA
// ============================================================================

/**
 * Compara duas strings de forma constante (prevenir timing attacks)
 */
export function secureCompare(a: string, b: string): boolean {
  const aBytes = toBytes(a);
  const bBytes = toBytes(b);

  if (aBytes.length !== bBytes.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i] ^ bBytes[i];
  }

  return result === 0;
}

// ============================================================================
// ENCRYPTION SIMÉTRICA (AES-256-GCM via Web Crypto API)
// ============================================================================

/**
 * Encripta dados usando AES-256-GCM
 * 
 * NOTA: Para Node.js, usar crypto.createCipheriv com 'aes-256-gcm'
 * Esta implementação usa Web Crypto API para compatibilidade browser/node
 * 
 * @param data - Dados para encriptar
 * @param key - Chave de 32 bytes (256 bits)
 * @returns Dados encriptados com IV e tag
 */
export async function encrypt(
  data: Uint8Array,
  key: Uint8Array
): Promise<EncryptedData> {
  if (key.length !== 32) {
    throw new Error('Key must be 32 bytes (256 bits)');
  }

  if (data.length > CRYPTO_CONSTANTS.MAX_ENCRYPT_SIZE) {
    throw new Error('Data exceeds maximum encryption size');
  }

  // Gerar nonce único para cada operação
  const iv = generateRandomBytes(CRYPTO_CONSTANTS.AES_NONCE_LENGTH);

  // Usar Web Crypto API se disponível (Node.js 15+, browsers modernos)
  if (typeof crypto !== 'undefined' && 'subtle' in crypto) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      data
    );

    const encryptedBytes = new Uint8Array(encrypted);
    
    // Extrair tag (últimos 16 bytes)
    const tag = encryptedBytes.slice(-CRYPTO_CONSTANTS.AES_TAG_LENGTH);
    const ciphertext = encryptedBytes.slice(0, -CRYPTO_CONSTANTS.AES_TAG_LENGTH);

    return {
      ciphertext: toBase64(ciphertext),
      iv: toBase64(iv),
      tag: toBase64(tag),
      algorithm: 'AES-256-GCM',
    };
  }

  // Fallback para ambientes sem Web Crypto (usando tweetnacl secretbox)
  // Nota: secretbox usa XSalsa20-Poly1305, que também é seguro
  const nonce = iv.slice(0, 24); // tweetnacl usa 24 bytes
  const box = nacl.secretbox(data, nonce, key);
  
  return {
    ciphertext: toBase64(box.slice(16)), // Conteúdo sem prefixo
    iv: toBase64(nonce),
    tag: toBase64(box.slice(0, 16)), // Tag de autenticação
    algorithm: 'XSalsa20-Poly1305',
  };
}

/**
 * Decripta dados usando AES-256-GCM
 * 
 * @param encryptedData - Dados encriptados com IV e tag
 * @param key - Chave de 32 bytes
 * @returns Dados decriptados
 */
export async function decrypt(
  encryptedData: EncryptedData,
  key: Uint8Array
): Promise<Uint8Array> {
  if (key.length !== 32) {
    throw new Error('Key must be 32 bytes (256 bits)');
  }

  const ciphertext = fromBase64(encryptedData.ciphertext);
  const iv = fromBase64(encryptedData.iv);
  const tag = fromBase64(encryptedData.tag);

  if (typeof crypto !== 'undefined' && 'subtle' in crypto) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // Reunir ciphertext + tag para Web Crypto
    const encryptedBytes = new Uint8Array(ciphertext.length + tag.length);
    encryptedBytes.set(ciphertext);
    encryptedBytes.set(tag, ciphertext.length);

    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        encryptedBytes
      );

      return new Uint8Array(decrypted);
    } catch (error) {
      throw new Error('Decryption failed: invalid tag or corrupted data');
    }
  }

  // Fallback tweetnacl
  const nonce = iv.slice(0, 24);
  const box = new Uint8Array(tag.length + ciphertext.length);
  box.set(tag);
  box.set(ciphertext, tag.length);

  const decrypted = nacl.secretbox.open(box, nonce, key);
  if (!decrypted) {
    throw new Error('Decryption failed: invalid tag or corrupted data');
  }

  return decrypted;
}

/**
 * Gera uma chave mestra segura para envelope encryption
 */
export function generateMasterKey(): { key: Uint8Array; keyId: string } {
  const key = generateRandomBytes(32);
  const keyId = `mk_${toBase64(generateRandomBytes(16)).replace(/[/+]/g, '').slice(0, 16)}`;
  return { key, keyId };
}

// ============================================================================
// KEY WRAPPING (Envelope Encryption)
// ============================================================================

/**
 * Encripta uma chave de dados usando a chave mestra
 * Isso permite rotação de chaves mestras sem re-encriptar todos os dados
 */
export async function wrapKey(
  dataKey: Uint8Array,
  masterKey: Uint8Array
): Promise<EncryptedData> {
  return encrypt(dataKey, masterKey);
}

/**
 * Decripta uma chave de dados usando a chave mestra
 */
export async function unwrapKey(
  wrappedKey: EncryptedData,
  masterKey: Uint8Array
): Promise<Uint8Array> {
  return decrypt(wrappedKey, masterKey);
}

// ============================================================================
// TOTP (Time-based One-Time Password)
// ============================================================================

/**
 * Gera um código TOTP para MFA
 * Baseado em RFC 6238
 */
export function generateTOTP(
  secret: Uint8Array,
  timestamp: number = Date.now(),
  period: number = 30,
  digits: number = 6
): string {
  const counter = Math.floor(timestamp / 1000 / period);
  const counterBytes = new Uint8Array(8);
  
  // Big-endian counter
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = counter & 0xff;
    counter >>>= 8;
  }

  const hmacResult = hmac(secret, counterBytes);
  const offset = hmacResult[hmacResult.length - 1] & 0x0f;
  
  const binary = ((hmacResult[offset] & 0x7f) << 24) |
    ((hmacResult[offset + 1] & 0xff) << 16) |
    ((hmacResult[offset + 2] & 0xff) << 8) |
    (hmacResult[offset + 3] & 0xff);

  const otp = (binary % Math.pow(10, digits)).toString().padStart(digits, '0');
  return otp;
}

/**
 * Verifica um código TOTP
 * Permite window de ±1 período para clock skew
 */
export function verifyTOTP(
  secret: Uint8Array,
  token: string,
  timestamp: number = Date.now(),
  window: number = 1
): boolean {
  const period = 30;
  const digits = 6;
  
  for (let i = -window; i <= window; i++) {
    const checkTime = timestamp + (i * period * 1000);
    const expected = generateTOTP(secret, checkTime, period, digits);
    if (secureCompare(token, expected)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Gera um segredo TOTP seguro para MFA
 */
export function generateTOTPSecret(): { secret: Uint8Array; base32: string } {
  const secret = generateRandomBytes(20); // 160 bits para TOTP
  const base32 = toBase32(secret);
  return { secret, base32 };
}

/**
 * Converte bytes para Base32 (para TOTP secrets)
 */
function toBase32(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  let base32 = '';

  for (const byte of bytes) {
    bits += byte.toString(2).padStart(8, '0');
  }

  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    base32 += alphabet[parseInt(chunk, 2)];
  }

  return base32;
}

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // Constants
  CRYPTO_CONSTANTS,
  
  // Encoding
  toBase64,
  fromBase64,
  toBytes,
  toString,
  generateRandomBytes,
  
  // Hashing
  sha256Hash,
  sha256Bytes,
  hmacSha256,
  
  // Key derivation
  deriveKey,
  generateSalt,
  verifyPassword,
  
  // Comparison
  secureCompare,
  
  // Encryption
  encrypt,
  decrypt,
  generateMasterKey,
  wrapKey,
  unwrapKey,
  
  // TOTP
  generateTOTP,
  verifyTOTP,
  generateTOTPSecret,
};

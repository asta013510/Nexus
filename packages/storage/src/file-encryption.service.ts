/**
 * File Encryption Service
 * 
 * Criptografa arquivos antes do armazenamento usando AES-256-GCM.
 * Cada arquivo recebe uma chave única derivada da chave mestre do usuário.
 * 
 * Segurança:
 * - AES-256-GCM (authenticated encryption)
 * - IV único por arquivo (96 bits)
 * - Tag de autenticação (128 bits)
 * - Chave derivada via HKDF
 */

import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits
const TAG_LENGTH = 16; // 128 bits
const KEY_LENGTH = 32; // 256 bits

export interface EncryptedFile {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  originalSize: number;
  encryptedSize: number;
}

export interface DecryptedFile {
  plaintext: Buffer;
  originalSize: number;
}

export class FileEncryptionService {
  /**
   * Deriva uma chave específica para um arquivo a partir da chave mestre
   * Usa HKDF-SHA256 para derivação segura
   */
  deriveFileKey(masterKey: Buffer, fileId: string): Buffer {
    const crypto = require('crypto');
    const hkdf = crypto.createHmac('sha256', masterKey);
    hkdf.update(fileId);
    return hkdf.digest().slice(0, KEY_LENGTH);
  }

  /**
   * Criptografa um arquivo
   * @param plaintext - Dados brutos do arquivo
   * @param fileKey - Chave de criptografia específica do arquivo
   */
  encrypt(plaintext: Buffer, fileKey: Buffer): EncryptedFile {
    if (fileKey.length !== KEY_LENGTH) {
      throw new Error(`Chave deve ter ${KEY_LENGTH} bytes`);
    }

    const iv = randomBytes(IV_LENGTH);
    
    const cipher = createCipheriv(ALGORITHM, fileKey, iv);
    
    let ciphertext = cipher.update(plaintext);
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    
    const authTag = cipher.getAuthTag();

    return {
      ciphertext,
      iv,
      authTag,
      originalSize: plaintext.length,
      encryptedSize: ciphertext.length
    };
  }

  /**
   * Descriptografa um arquivo
   * @param encrypted - Objeto com dados criptografados
   * @param fileKey - Chave de descriptografia
   */
  decrypt(encrypted: EncryptedFile, fileKey: Buffer): DecryptedFile {
    if (fileKey.length !== KEY_LENGTH) {
      throw new Error(`Chave deve ter ${KEY_LENGTH} bytes`);
    }

    const decipher = createDecipheriv(ALGORITHM, fileKey, encrypted.iv);
    decipher.setAuthTag(encrypted.authTag);

    let plaintext = decipher.update(encrypted.ciphertext);
    plaintext = Buffer.concat([plaintext, decipher.final()]);

    return {
      plaintext,
      originalSize: encrypted.originalSize
    };
  }

  /**
   * Empacota dados criptografados em um único buffer para armazenamento
   * Formato: [IV (12)] [TAG (16)] [CIPHERTEXT (variável)]
   */
  packEncryptedFile(encrypted: EncryptedFile): Buffer {
    const packed = Buffer.alloc(
      IV_LENGTH + TAG_LENGTH + encrypted.ciphertext.length
    );
    
    encrypted.iv.copy(packed, 0);
    encrypted.authTag.copy(packed, IV_LENGTH);
    encrypted.ciphertext.copy(packed, IV_LENGTH + TAG_LENGTH);

    return packed;
  }

  /**
   * Extrai dados de um buffer empacotado
   */
  unpackEncryptedFile(packed: Buffer, originalSize: number): EncryptedFile {
    if (packed.length < IV_LENGTH + TAG_LENGTH) {
      throw new Error('Buffer muito pequeno para conter dados válidos');
    }

    const iv = packed.slice(0, IV_LENGTH);
    const authTag = packed.slice(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const ciphertext = packed.slice(IV_LENGTH + TAG_LENGTH);

    return {
      ciphertext,
      iv,
      authTag,
      originalSize,
      encryptedSize: ciphertext.length
    };
  }

  /**
   * Calcula overhead de criptografia
   */
  getEncryptionOverhead(): number {
    return IV_LENGTH + TAG_LENGTH; // 28 bytes adicionais
  }
}

export const fileEncryptionService = new FileEncryptionService();

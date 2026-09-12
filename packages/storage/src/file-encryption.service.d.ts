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
export declare class FileEncryptionService {
    /**
     * Deriva uma chave específica para um arquivo a partir da chave mestre
     * Usa HKDF-SHA256 para derivação segura
     */
    deriveFileKey(masterKey: Buffer, fileId: string): Buffer;
    /**
     * Criptografa um arquivo
     * @param plaintext - Dados brutos do arquivo
     * @param fileKey - Chave de criptografia específica do arquivo
     */
    encrypt(plaintext: Buffer, fileKey: Buffer): EncryptedFile;
    /**
     * Descriptografa um arquivo
     * @param encrypted - Objeto com dados criptografados
     * @param fileKey - Chave de descriptografia
     */
    decrypt(encrypted: EncryptedFile, fileKey: Buffer): DecryptedFile;
    /**
     * Empacota dados criptografados em um único buffer para armazenamento
     * Formato: [IV (12)] [TAG (16)] [CIPHERTEXT (variável)]
     */
    packEncryptedFile(encrypted: EncryptedFile): Buffer;
    /**
     * Extrai dados de um buffer empacotado
     */
    unpackEncryptedFile(packed: Buffer, originalSize: number): EncryptedFile;
    /**
     * Calcula overhead de criptografia
     */
    getEncryptionOverhead(): number;
}
export declare const fileEncryptionService: FileEncryptionService;
//# sourceMappingURL=file-encryption.service.d.ts.map
/**
 * @zero/crypto - Módulo de Criptografia
 *
 * SECURITY: Wrapper seguro para operações criptográficas
 * NUNCA implementar algoritmos próprios - usar bibliotecas auditadas
 */
export declare const ARGON2_CONFIG: {
    readonly memoryCost: 65536;
    readonly timeCost: 3;
    readonly parallelism: 4;
    readonly hashLength: 32;
};
/**
 * Gera salt seguro para password hashing
 */
export declare function generateSalt(): string;
/**
 * Hash de senha usando Argon2id
 * SECURITY: Parâmetros hardcoded conforme OWASP recommendations
 */
export declare function hashPassword(password: string, salt?: string): Promise<string>;
/**
 * Verifica se senha corresponde ao hash
 * SECURITY: Constant-time comparison (feito pelo argon2)
 */
export declare function verifyPassword(password: string, hash: string): Promise<boolean>;
/**
 * Verifica se hash precisa ser re-hash (para upgrade de parâmetros)
 */
export declare function needsRehash(hash: string): boolean;
/**
 * Gera token seguro aleatório
 */
export declare function generateSecureToken(length?: number): string;
/**
 * Gera código numérico seguro (para TOTP/recovery codes)
 */
export declare function generateNumericCode(digits?: number): string;
/**
 * Hash SHA-256 seguro para dados não-sensíveis
 */
export declare function sha256(data: string): Promise<string>;
/**
 * Gera secret TOTP e retorna em formato base32
 */
export declare function generateTOTPSecret(): {
    secret: string;
    algorithm: string;
    digits: number;
    period: number;
};
/**
 * Verifica código TOTP
 * SECURITY: Constant-time comparison
 */
export declare function verifyTOTP(secret: string, code: string, window?: number): Promise<boolean>;
/**
 * Gera recovery codes
 */
export declare function generateRecoveryCodes(count?: number): string[];
/**
 * Comparison constante para prevenir timing attacks
 */
export declare function timingSafeCompare(a: string, b: string): boolean;
/**
 * Hash seguro para dados não-sensíveis (ex: identificar email sem expor)
 */
export declare function hashIdentifier(identifier: string, salt: string): Promise<string>;
/**
 * Deriva chave de encryption a partir de master key
 */
export declare function deriveKey(masterKey: string, salt: string, purpose: string): Promise<CryptoKey>;
/**
 * Encripta dados usando AES-256-GCM
 */
export declare function encrypt(data: string, key: CryptoKey): Promise<{
    ciphertext: string;
    iv: string;
    tag: string;
}>;
/**
 * Decripta dados usando AES-256-GCM
 */
export declare function decrypt(ciphertext: string, iv: string, tag: string, key: CryptoKey): Promise<string>;
export { hashPassword, verifyPassword, needsRehash, generateSalt, sha256, generateTOTPSecret, verifyTOTP, generateRecoveryCodes, timingSafeCompare, };
declare const _default: {
    hashPassword: typeof hashPassword;
    verifyPassword: typeof verifyPassword;
    needsRehash: typeof needsRehash;
    generateSalt: typeof generateSalt;
    generateSecureToken: typeof generateSecureToken;
    generateNumericCode: typeof generateNumericCode;
    hashIdentifier: typeof hashIdentifier;
    deriveKey: typeof deriveKey;
    encrypt: typeof encrypt;
    decrypt: typeof decrypt;
    ARGON2_CONFIG: {
        readonly memoryCost: 65536;
        readonly timeCost: 3;
        readonly parallelism: 4;
        readonly hashLength: 32;
    };
    sha256: typeof sha256;
    generateTOTPSecret: typeof generateTOTPSecret;
    verifyTOTP: typeof verifyTOTP;
    generateRecoveryCodes: typeof generateRecoveryCodes;
    timingSafeCompare: typeof timingSafeCompare;
};
export default _default;
//# sourceMappingURL=index.d.ts.map
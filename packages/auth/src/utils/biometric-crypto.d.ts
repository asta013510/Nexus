/**
 * ZERO - Utilitários de Criptografia para Biometria
 *
 * Funções para transformação irreversível de templates biométricos.
 */
/**
 * Gera um salt criptograficamente seguro.
 */
export declare function generateSalt(): Promise<string>;
/**
 * Aplica transformação irreversível ao template biométrico.
 * Combina embeddings com salt e aplica hash criptográfico.
 */
export declare function hashTemplate(template: {
    embeddings: Float32Array;
    salt: string;
}): Promise<string>;
/**
 * Compara dois templates de forma segura (constant-time).
 */
export declare function compareTemplates(template1: string, template2: string): Promise<boolean>;
//# sourceMappingURL=biometric-crypto.d.ts.map
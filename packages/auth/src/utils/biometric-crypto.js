"use strict";
/**
 * ZERO - Utilitários de Criptografia para Biometria
 *
 * Funções para transformação irreversível de templates biométricos.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateSalt = generateSalt;
exports.hashTemplate = hashTemplate;
exports.compareTemplates = compareTemplates;
const crypto_1 = require("crypto");
/**
 * Gera um salt criptograficamente seguro.
 */
async function generateSalt() {
    return (0, crypto_1.randomBytes)(32).toString('hex');
}
/**
 * Aplica transformação irreversível ao template biométrico.
 * Combina embeddings com salt e aplica hash criptográfico.
 */
async function hashTemplate(template) {
    const encoder = new TextEncoder();
    // Converte embeddings para array normal
    const embeddingsArray = Array.from(template.embeddings);
    // Combina embeddings + salt
    const data = JSON.stringify({
        embeddings: embeddingsArray,
        salt: template.salt
    });
    // Hash SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}
/**
 * Compara dois templates de forma segura (constant-time).
 */
async function compareTemplates(template1, template2) {
    if (template1.length !== template2.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < template1.length; i++) {
        diff |= template1.charCodeAt(i) ^ template2.charCodeAt(i);
    }
    return diff === 0;
}
//# sourceMappingURL=biometric-crypto.js.map
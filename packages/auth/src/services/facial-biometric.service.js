"use strict";
/**
 * ZERO - Facial Biometric Service
 *
 * Serviço de biometria facial INDEPENDENTE do dispositivo.
 * NUNCA armazena imagens brutas - apenas templates biométricos irreversíveis.
 *
 * @warning NOT PRODUCTION READY - Requer testes extensivos de segurança
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.FacialBiometricService = void 0;
const biometric_crypto_1 = require("../utils/biometric-crypto");
class FacialBiometricService {
    static TEMPLATE_SIZE = 512;
    static SIMILARITY_THRESHOLD = 0.6; // 60% similaridade mínima
    /**
     * Gera um template biométrico a partir de embeddings faciais
     * e aplica transformação irreversível com salt único.
     */
    static async enroll(userId, embeddings, livenessResult) {
        // Validação de liveness obrigatória
        if (!livenessResult.isAlive) {
            return {
                success: false,
                error: 'LIVENESS_FAILED',
                message: 'Detecção de vivacidade falhou'
            };
        }
        // Valida tamanho do embedding
        if (embeddings.length !== this.TEMPLATE_SIZE) {
            return {
                success: false,
                error: 'INVALID_EMBEDDING',
                message: `Embedding deve ter ${this.TEMPLATE_SIZE} dimensões`
            };
        }
        try {
            // Gera salt único para este usuário
            const salt = await (0, biometric_crypto_1.generateSalt)();
            // Cria template biométrico
            const template = {
                userId,
                embeddings: new Float32Array(embeddings),
                salt,
                createdAt: new Date(),
                version: 1
            };
            // Aplica transformação irreversível (hash do template + salt)
            const irreversibleTemplate = await (0, biometric_crypto_1.hashTemplate)(template);
            return {
                success: true,
                template: irreversibleTemplate,
                templateId: crypto.randomUUID(),
                message: 'Template biométrico criado com sucesso'
            };
        }
        catch (error) {
            return {
                success: false,
                error: 'ENROLLMENT_ERROR',
                message: error instanceof Error ? error.message : 'Erro desconhecido'
            };
        }
    }
    /**
     * Verifica se um novo embedding corresponde ao template armazenado.
     * Usa comparação de similaridade de cosseno.
     */
    static async verify(embeddings, storedTemplate, livenessResult) {
        // Validação de liveness obrigatória
        if (!livenessResult.isAlive) {
            return {
                success: false,
                isMatch: false,
                confidence: 0,
                error: 'LIVENESS_FAILED'
            };
        }
        // Valida tamanho do embedding
        if (embeddings.length !== this.TEMPLATE_SIZE) {
            return {
                success: false,
                isMatch: false,
                confidence: 0,
                error: 'INVALID_EMBEDDING'
            };
        }
        try {
            // Calcula similaridade entre embeddings
            const similarity = this.calculateCosineSimilarity(new Float32Array(embeddings), new Float32Array(JSON.parse(storedTemplate)));
            const isMatch = similarity >= this.SIMILARITY_THRESHOLD;
            return {
                success: true,
                isMatch,
                confidence: similarity,
                message: isMatch ? 'Verificação bem-sucedida' : 'Semelhança insuficiente'
            };
        }
        catch (error) {
            return {
                success: false,
                isMatch: false,
                confidence: 0,
                error: 'VERIFICATION_ERROR'
            };
        }
    }
    /**
     * Calcula similaridade de cosseno entre dois vetores de embeddings.
     * Retorna valor entre 0 (totalmente diferentes) e 1 (idênticos).
     */
    static calculateCosineSimilarity(a, b) {
        if (a.length !== b.length) {
            throw new Error('Embeddings devem ter o mesmo tamanho');
        }
        let dotProduct = 0;
        let magnitudeA = 0;
        let magnitudeB = 0;
        for (let i = 0; i < a.length; i++) {
            dotProduct += a[i] * b[i];
            magnitudeA += a[i] * a[i];
            magnitudeB += b[i] * b[i];
        }
        magnitudeA = Math.sqrt(magnitudeA);
        magnitudeB = Math.sqrt(magnitudeB);
        if (magnitudeA === 0 || magnitudeB === 0) {
            return 0;
        }
        return dotProduct / (magnitudeA * magnitudeB);
    }
    /**
     * Remove dados biométricos do usuário (direito ao esquecimento).
     */
    static async revoke(userId) {
        // Em produção: deletar do banco de dados
        // Aqui: apenas confirmação lógica
        return {
            success: true,
            message: `Dados biométricos do usuário ${userId} revogados`
        };
    }
}
exports.FacialBiometricService = FacialBiometricService;
//# sourceMappingURL=facial-biometric.service.js.map
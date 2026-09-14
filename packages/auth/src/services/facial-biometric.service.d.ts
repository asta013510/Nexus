/**
 * ZERO - Facial Biometric Service
 *
 * Serviço de biometria facial INDEPENDENTE do dispositivo.
 * NUNCA armazena imagens brutas - apenas templates biométricos irreversíveis.
 *
 * @warning NOT PRODUCTION READY - Requer testes extensivos de segurança
 */
import type { LivenessResult, EnrollmentResult, VerificationResult } from '../types/facial-biometric';
export declare class FacialBiometricService {
    private static readonly TEMPLATE_SIZE;
    private static readonly SIMILARITY_THRESHOLD;
    /**
     * Gera um template biométrico a partir de embeddings faciais
     * e aplica transformação irreversível com salt único.
     */
    static enroll(userId: string, embeddings: number[], livenessResult: LivenessResult): Promise<EnrollmentResult>;
    /**
     * Verifica se um novo embedding corresponde ao template armazenado.
     * Usa comparação de similaridade de cosseno.
     */
    static verify(embeddings: number[], storedTemplate: string, livenessResult: LivenessResult): Promise<VerificationResult>;
    /**
     * Calcula similaridade de cosseno entre dois vetores de embeddings.
     * Retorna valor entre 0 (totalmente diferentes) e 1 (idênticos).
     */
    private static calculateCosineSimilarity;
    /**
     * Remove dados biométricos do usuário (direito ao esquecimento).
     */
    static revoke(userId: string): Promise<{
        success: boolean;
        message: string;
    }>;
}
//# sourceMappingURL=facial-biometric.service.d.ts.map
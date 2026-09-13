/**
 * ZERO - Tipos para Biometria Facial
 */
export interface FacialTemplate {
    userId: string;
    embeddings: Float32Array;
    salt: string;
    createdAt: Date;
    version: number;
}
export interface LivenessResult {
    isAlive: boolean;
    confidence: number;
    reason: string;
    scores?: {
        motion: number;
        texture: number;
        depth?: number;
        challenge?: number;
    };
    nonce?: string;
}
export interface LivenessChallenge {
    action: 'blink' | 'turn_head_left' | 'turn_head_right' | 'smile' | 'nod';
    nonce: string;
    expiresAt: Date;
    instructions: string;
}
export interface EnrollmentResult {
    success: boolean;
    template?: string;
    templateId?: string;
    error?: 'LIVENESS_FAILED' | 'INVALID_EMBEDDING' | 'ENROLLMENT_ERROR';
    message?: string;
}
export interface VerificationResult {
    success: boolean;
    isMatch: boolean;
    confidence: number;
    error?: 'LIVENESS_FAILED' | 'INVALID_EMBEDDING' | 'VERIFICATION_ERROR';
    message?: string;
}
export interface FacialBiometricData {
    id: string;
    userId: string;
    templateHash: string;
    livenessScore: number;
    enrolledAt: Date;
    lastUsedAt?: Date;
    version: number;
}
//# sourceMappingURL=facial-biometric.d.ts.map
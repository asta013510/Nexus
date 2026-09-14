/**
 * ZERO - Liveness Detection Service
 *
 * Detecção de vivacidade para prevenir ataques com:
 * - Fotos estáticas
 * - Vídeos/replay attacks
 * - Máscaras 3D
 * - Deepfakes
 *
 * @warning NOT PRODUCTION READY - Algoritmos básicos, requer ML avançado
 */
import type { LivenessResult, LivenessChallenge } from '../types/facial-biometric';
export declare class LivenessDetectionService {
    private static readonly MAX_CHALLENGE_ATTEMPTS;
    private static readonly CHALLENGE_TIMEOUT_MS;
    /**
     * Gera um desafio aleatório de liveness.
     * O usuário deve executar a ação solicitada.
     */
    static generateChallenge(): LivenessChallenge;
    /**
     * Analisa resultados de detecção de liveness.
     * Combina múltiplos sinais para determinar se é uma pessoa viva.
     */
    static analyzeLiveness(challenge: LivenessChallenge, userResponse: {
        action: string;
        confidence: number;
        timestamp: Date;
        motionDetected: boolean;
        textureScore: number;
        depthScore?: number;
    }): Promise<LivenessResult>;
    /**
     * Detecta possíveis ataques de replay analisando padrões temporais.
     */
    static detectReplayAttack(frames: Array<{
        timestamp: number;
        hash: string;
        similarity: number;
    }>): boolean;
    /**
     * Análise básica de textura para detectar telas/monitores.
     * Scores baixos indicam possível ataque com foto/vídeo em tela.
     */
    static analyzeTexture(indicators: {
        moirePattern: number;
        reflectance: number;
        edgeSharpness: number;
    }): number;
    private static getInstructions;
}
//# sourceMappingURL=liveness-detection.service.d.ts.map
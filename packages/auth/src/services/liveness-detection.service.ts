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

export class LivenessDetectionService {
  private static readonly MAX_CHALLENGE_ATTEMPTS = 3;
  private static readonly CHALLENGE_TIMEOUT_MS = 10000;

  /**
   * Gera um desafio aleatório de liveness.
   * O usuário deve executar a ação solicitada.
   */
  static generateChallenge(): LivenessChallenge {
    const challenges: Array<'blink' | 'turn_head_left' | 'turn_head_right' | 'smile' | 'nod'> = [
      'blink',
      'turn_head_left',
      'turn_head_right',
      'smile',
      'nod'
    ];

    const selectedChallenge = challenges[Math.floor(Math.random() * challenges.length)];
    const nonce = crypto.randomUUID();

    return {
      action: selectedChallenge,
      nonce,
      expiresAt: new Date(Date.now() + this.CHALLENGE_TIMEOUT_MS),
      instructions: this.getInstructions(selectedChallenge)
    };
  }

  /**
   * Analisa resultados de detecção de liveness.
   * Combina múltiplos sinais para determinar se é uma pessoa viva.
   */
  static async analyzeLiveness(
    challenge: LivenessChallenge,
    userResponse: {
      action: string;
      confidence: number;
      timestamp: Date;
      motionDetected: boolean;
      textureScore: number;
      depthScore?: number;
    }
  ): Promise<LivenessResult> {
    // Verifica se o desafio expirou
    if (new Date() > challenge.expiresAt) {
      return {
        isAlive: false,
        confidence: 0,
        reason: 'CHALLENGE_EXPIRED',
        scores: {
          motion: 0,
          texture: 0,
          challenge: 0
        }
      };
    }

    // Verifica se a ação corresponde ao desafio
    if (userResponse.action !== challenge.action) {
      return {
        isAlive: false,
        confidence: 0,
        reason: 'INVALID_ACTION',
        scores: {
          motion: 0,
          texture: 0,
          challenge: 0
        }
      };
    }

    // Calcula scores compostos
    const motionScore = userResponse.motionDetected ? Math.min(1.0, userResponse.confidence) : 0;
    const textureScore = Math.max(0, Math.min(1.0, userResponse.textureScore));
    const depthScore = userResponse.depthScore ?? 0.5; // Default se não disponível
    const challengeScore = userResponse.confidence;

    // Score final ponderado
    const finalScore = (
      (motionScore * 0.25) +
      (textureScore * 0.25) +
      (depthScore * 0.25) +
      (challengeScore * 0.25)
    );

    const isAlive = finalScore >= 0.6; // Threshold de 60%

    return {
      isAlive,
      confidence: finalScore,
      reason: isAlive ? 'LIVENESS_VERIFIED' : 'LOW_CONFIDENCE',
      scores: {
        motion: motionScore,
        texture: textureScore,
        depth: depthScore,
        challenge: challengeScore
      },
      nonce: challenge.nonce
    };
  }

  /**
   * Detecta possíveis ataques de replay analisando padrões temporais.
   */
  static detectReplayAttack(
    frames: Array<{
      timestamp: number;
      hash: string;
      similarity: number;
    }>
  ): boolean {
    // Se muitos frames são idênticos, possível replay
    const identicalFrames = frames.filter((frame, idx) => {
      if (idx === 0) return false;
      return frame.hash === frames[idx - 1].hash && frame.similarity > 0.99;
    });

    // Mais de 30% de frames idênticos indica replay
    return identicalFrames.length > frames.length * 0.3;
  }

  /**
   * Análise básica de textura para detectar telas/monitores.
   * Scores baixos indicam possível ataque com foto/vídeo em tela.
   */
  static analyzeTexture(indicators: {
    moirePattern: number; // 0-1, 1 = forte padrão Moiré (tela)
    reflectance: number;  // 0-1, 1 = reflexos artificiais
    edgeSharpness: number; // 0-1, 1 = bordas muito nítidas (não-natural)
  }): number {
    const moirePenalty = indicators.moirePattern * 0.4;
    const reflectancePenalty = indicators.reflectance * 0.3;
    const sharpnessPenalty = indicators.edgeSharpness * 0.3;

    const textureScore = 1.0 - (moirePenalty + reflectancePenalty + sharpnessPenalty);
    
    return Math.max(0, Math.min(1.0, textureScore));
  }

  private static getInstructions(action: string): string {
    const instructions: Record<string, string> = {
      blink: 'Pisque os olhos lentamente',
      turn_head_left: 'Vire a cabeça para a esquerda',
      turn_head_right: 'Vire a cabeça para a direita',
      smile: 'Sorria naturalmente',
      nod: 'Acene com a cabeça para cima e para baixo'
    };
    return instructions[action] || 'Siga as instruções na tela';
  }
}

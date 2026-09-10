/**
 * Middleware de Autenticação
 *
 * RESPONSABILIDADES:
 * - Validar JWT access token
 * - Extrair sessão do request
 * - Proteger rotas que exigem autenticação
 * - Renovar tokens quando necessário
 */
import { Request, Response, NextFunction } from 'express';
import type { JWTPayload } from '@zero/auth';
export interface AuthenticatedRequest extends Request {
    auth?: {
        userId: string;
        sessionId: string;
        deviceId: string;
        payload: JWTPayload;
    };
}
/**
 * Extrai sessão do request (JWT ou cookie)
 */
export declare function getSessionFromRequest(req: Request): {
    userId: string;
    sessionId: string;
    deviceId: string;
    createdAt: Date;
} | null;
/**
 * Middleware que exige autenticação
 * Adiciona auth ao request se válido
 */
export declare function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void;
/**
 * Middleware para operações sensíveis (step-up auth)
 * Pode exigir re-autenticação recente
 */
export declare function requireRecentAuth(maxAgeMs?: number): (req: AuthenticatedRequest, res: Response, next: NextFunction) => void;
/**
 * Middleware opcional de autenticação
 * Adiciona auth se presente, mas não falha se ausente
 */
export declare function optionalAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void;
//# sourceMappingURL=auth.d.ts.map
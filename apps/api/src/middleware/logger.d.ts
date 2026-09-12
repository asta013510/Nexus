/**
 * Middleware de Logging de Requests
 *
 * SECURITY: Log estruturado SEM dados sensíveis
 * NUNCA logar: senhas, tokens, chaves, dados biométricos
 */
import { Request, Response, NextFunction } from 'express';
export interface LoggedRequest extends Request {
    requestId: string;
    startTime: number;
}
export declare function requestLogger(req: LoggedRequest, res: Response, next: NextFunction): void;
/**
 * Logger seguro para uso em serviços
 * SECURITY: Sanitiza dados antes de logar
 */
export declare function safeLog(level: 'info' | 'warn' | 'error', message: string, data?: Record<string, unknown>): void;
//# sourceMappingURL=logger.d.ts.map
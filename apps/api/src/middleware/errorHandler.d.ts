/**
 * Error Handler Middleware
 *
 * SECURITY: Não vazar detalhes internos para o cliente
 * Logs completos apenas no servidor
 */
import { Request, Response, NextFunction } from 'express';
export declare class AppError extends Error {
    statusCode: number;
    isOperational: boolean;
    code?: string;
    constructor(message: string, statusCode?: number, code?: string, isOperational?: boolean);
}
export declare class BadRequestError extends AppError {
    constructor(message: string, code?: string);
}
export declare class UnauthorizedError extends AppError {
    constructor(message: string, code?: string);
}
export declare class ForbiddenError extends AppError {
    constructor(message: string, code?: string);
}
export declare class NotFoundError extends AppError {
    constructor(message: string, code?: string);
}
export declare class ConflictError extends AppError {
    constructor(message: string, code?: string);
}
export declare class TooManyRequestsError extends AppError {
    constructor(message: string, code?: string);
}
export declare function errorHandler(err: Error | AppError, req: Request, res: Response, _next: NextFunction): void;
/**
 * Async handler wrapper para evitar try/catch boilerplate
 */
export declare function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<void>): (req: Request, res: Response, next: NextFunction) => void;
//# sourceMappingURL=errorHandler.d.ts.map
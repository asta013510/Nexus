/**
 * Error Handler Middleware
 *
 * SECURITY: Não vazar detalhes internos para o cliente
 * Logs completos apenas no servidor
 */
import { safeLog } from './logger.js';
export class AppError extends Error {
    statusCode;
    isOperational;
    code;
    constructor(message, statusCode = 500, code, isOperational = true) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.isOperational = isOperational;
        Error.captureStackTrace(this, this.constructor);
    }
}
export class BadRequestError extends AppError {
    constructor(message, code) {
        super(message, 400, code);
    }
}
export class UnauthorizedError extends AppError {
    constructor(message, code) {
        super(message, 401, code);
    }
}
export class ForbiddenError extends AppError {
    constructor(message, code) {
        super(message, 403, code);
    }
}
export class NotFoundError extends AppError {
    constructor(message, code) {
        super(message, 404, code);
    }
}
export class ConflictError extends AppError {
    constructor(message, code) {
        super(message, 409, code);
    }
}
export class TooManyRequestsError extends AppError {
    constructor(message, code) {
        super(message, 429, code);
    }
}
export function errorHandler(err, req, res, _next) {
    // Log completo no servidor (com stack trace)
    safeLog('error', `Error em ${req.method} ${req.path}`, {
        error: err.message,
        stack: err.stack,
        code: err.code,
        statusCode: err.statusCode,
    });
    // Determinar status code
    const statusCode = err.statusCode || 500;
    const isOperational = err.isOperational !== false;
    // Resposta para o cliente (sem detalhes internos!)
    if (isOperational) {
        // Erro operacional conhecido - mensagem segura
        res.status(statusCode).json({
            error: getErrorName(statusCode),
            message: err.message,
            code: err.code,
            requestId: res.getHeader('X-Request-Id'),
        });
    }
    else {
        // Erro desconhecido ou interno - mensagem genérica
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Ocorreu um erro interno. Nossa equipe foi notificada.',
            requestId: res.getHeader('X-Request-Id'),
        });
    }
}
function getErrorName(statusCode) {
    const errorNames = {
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Not Found',
        409: 'Conflict',
        429: 'Too Many Requests',
        500: 'Internal Server Error',
        503: 'Service Unavailable',
    };
    return errorNames[statusCode] || 'Error';
}
/**
 * Async handler wrapper para evitar try/catch boilerplate
 */
export function asyncHandler(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}
//# sourceMappingURL=errorHandler.js.map
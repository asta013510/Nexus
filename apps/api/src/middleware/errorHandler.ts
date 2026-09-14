/**
 * Error Handler Middleware
 * 
 * SECURITY: Não vazar detalhes internos para o cliente
 * Logs completos apenas no servidor
 */

import { Request, Response, NextFunction } from 'express';
import { safeLog } from './logger.js';

export class AppError extends Error {
  statusCode: number;
  isOperational: boolean;
  code?: string;

  constructor(
    message: string,
    statusCode: number = 500,
    code?: string,
    isOperational: boolean = true
  ) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

export class BadRequestError extends AppError {
  constructor(message: string, code?: string) {
    super(message, 400, code);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message: string, code?: string) {
    super(message, 401, code);
  }
}

export class ForbiddenError extends AppError {
  constructor(message: string, code?: string) {
    super(message, 403, code);
  }
}

export class NotFoundError extends AppError {
  constructor(message: string, code?: string) {
    super(message, 404, code);
  }
}

export class ConflictError extends AppError {
  constructor(message: string, code?: string) {
    super(message, 409, code);
  }
}

export class TooManyRequestsError extends AppError {
  constructor(message: string, code?: string) {
    super(message, 429, code);
  }
}

export function errorHandler(
  err: Error | AppError,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  // Log completo no servidor (com stack trace)
  safeLog('error', `Error em ${req.method} ${req.path}`, {
    error: err.message,
    stack: err.stack,
    code: (err as AppError).code,
    statusCode: (err as AppError).statusCode,
  });

  // Determinar status code
  const statusCode = (err as AppError).statusCode || 500;
  const isOperational = (err as AppError).isOperational !== false;

  // Resposta para o cliente (sem detalhes internos!)
  if (isOperational) {
    // Erro operacional conhecido - mensagem segura
    res.status(statusCode).json({
      error: getErrorName(statusCode),
      message: err.message,
      code: (err as AppError).code,
      requestId: res.getHeader('X-Request-Id'),
    });
  } else {
    // Erro desconhecido ou interno - mensagem genérica
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Ocorreu um erro interno. Nossa equipe foi notificada.',
      requestId: res.getHeader('X-Request-Id'),
    });
  }
}

function getErrorName(statusCode: number): string {
  const errorNames: Record<number, string> = {
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
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

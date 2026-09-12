/**
 * Utils de Geração e Verificação de Tokens JWT
 * 
 * Usa biblioteca 'jose' para operações JWT seguras
 */

import { SignJWT, jwtVerify } from 'jose';
import { AUTH_CONSTANTS } from '../constants';
import type { JWTPayload, RefreshTokenPayload, TokenOptions, AuthError } from '../types';

// Chave secreta para JWT (em produção, usar variável de ambiente)
let JWT_SECRET_KEY: import('crypto').webcrypto.CryptoKey | null = null;

/**
 * Inicializa a chave JWT a partir de um segredo
 * Deve ser chamado uma vez no startup da aplicação
 */
export async function initializeJWTSecret(secret: string): Promise<void> {
  const encoder = new TextEncoder();
  JWT_SECRET_KEY = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

/**
 * Gera token de acesso JWT
 */
export async function generateAccessToken(options: TokenOptions): Promise<string> {
  if (!JWT_SECRET_KEY) {
    throw new Error('JWT secret não inicializado. Chame initializeJWTSecret primeiro.');
  }

  const now = Math.floor(Date.now() / 1000);
  
  const payload: JWTPayload = {
    sub: options.userId,
    sid: options.sessionId,
    typ: 'access',
    iat: now,
    exp: now + AUTH_CONSTANTS.ACCESS_TOKEN_EXPIRY,
    iss: AUTH_CONSTANTS.JWT_ISSUER,
    aud: AUTH_CONSTANTS.JWT_AUDIENCE,
    mfa: options.mfaVerified,
  };

  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime(`${AUTH_CONSTANTS.ACCESS_TOKEN_EXPIRY}s`)
    .setIssuer(AUTH_CONSTANTS.JWT_ISSUER)
    .setAudience(AUTH_CONSTANTS.JWT_AUDIENCE)
    .sign(JWT_SECRET_KEY);
}

/**
 * Gera refresh token JWT
 */
export async function generateRefreshToken(options: TokenOptions): Promise<string> {
  if (!JWT_SECRET_KEY) {
    throw new Error('JWT secret não inicializado. Chame initializeJWTSecret primeiro.');
  }

  const now = Math.floor(Date.now() / 1000);
  const counter = options.counter ?? 0;
  
  const payload: RefreshTokenPayload = {
    sub: options.userId,
    sid: options.sessionId,
    typ: 'refresh',
    iat: now,
    exp: now + AUTH_CONSTANTS.REFRESH_TOKEN_EXPIRY,
    iss: AUTH_CONSTANTS.JWT_ISSUER,
    aud: AUTH_CONSTANTS.JWT_AUDIENCE,
    counter,
  };

  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime(`${AUTH_CONSTANTS.REFRESH_TOKEN_EXPIRY}s`)
    .setIssuer(AUTH_CONSTANTS.JWT_ISSUER)
    .setAudience(AUTH_CONSTANTS.JWT_AUDIENCE)
    .sign(JWT_SECRET_KEY);
}

/**
 * Gera ambos os tokens (access + refresh)
 */
export async function generateAuthTokens(options: TokenOptions): Promise<{
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  refreshExpiresAt: Date;
}> {
  const [accessToken, refreshToken] = await Promise.all([
    generateAccessToken(options),
    generateRefreshToken(options),
  ]);

  return {
    accessToken,
    refreshToken,
    expiresAt: new Date(Date.now() + AUTH_CONSTANTS.ACCESS_TOKEN_EXPIRY * 1000),
    refreshExpiresAt: new Date(Date.now() + AUTH_CONSTANTS.REFRESH_TOKEN_EXPIRY * 1000),
  };
}

/**
 * Verifica e decodifica token JWT
 * Retorna o payload se válido, ou erro se inválido/expirado
 */
export async function verifyJWT<T extends JWTPayload | RefreshTokenPayload>(
  token: string
): Promise<{ valid: true; payload: T } | { valid: false; error: AuthError }> {
  if (!JWT_SECRET_KEY) {
    return {
      valid: false,
      error: { code: 'INTERNAL_ERROR', message: 'Configuração de autenticação inválida' },
    };
  }

  try {
    const { payload } = await jwtVerify(token, JWT_SECRET_KEY, {
      issuer: AUTH_CONSTANTS.JWT_ISSUER,
      audience: AUTH_CONSTANTS.JWT_AUDIENCE,
    });

    // Type assertion segura após verificação
    return { valid: true, payload: payload as T };
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === 'JWTExpired') {
        return {
          valid: false,
          error: { code: 'SESSION_EXPIRED', message: 'Sessão expirada' },
        };
      }
      if (error.name === 'JOSEError') {
        return {
          valid: false,
          error: { code: 'SESSION_INVALID', message: 'Token inválido' },
        };
      }
    }

    return {
      valid: false,
      error: { code: 'SESSION_INVALID', message: 'Token inválido' },
    };
  }
}

/**
 * Decodifica token sem verificar assinatura (apenas para debugging/logging)
 * NUNCA use isso para decisões de segurança!
 */
export function decodeJWT<T>(token: string): T | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const payload = parts[1];
    const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded) as T;
  } catch {
    return null;
  }
}

/**
 * Extrai tipo do token (access ou refresh)
 */
export function getTokenType(token: string): 'access' | 'refresh' | 'unknown' {
  const decoded = decodeJWT<{ typ?: string }>(token);
  if (decoded?.typ === 'access') {
    return 'access';
  }
  if (decoded?.typ === 'refresh') {
    return 'refresh';
  }
  return 'unknown';
}

/**
 * Verifica se token está próximo de expirar (menos de 2 minutos)
 */
export function isTokenExpiringSoon(token: string): boolean {
  const decoded = decodeJWT<{ exp?: number }>(token);
  if (!decoded?.exp) {
    return false;
  }

  const now = Math.floor(Date.now() / 1000);
  const timeUntilExpiry = decoded.exp - now;
  
  // Menos de 2 minutos
  return timeUntilExpiry < 120;
}

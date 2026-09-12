"use strict";
/**
 * Utils de Geração e Verificação de Tokens JWT
 *
 * Usa biblioteca 'jose' para operações JWT seguras
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.initializeJWTSecret = initializeJWTSecret;
exports.generateAccessToken = generateAccessToken;
exports.generateRefreshToken = generateRefreshToken;
exports.generateAuthTokens = generateAuthTokens;
exports.verifyJWT = verifyJWT;
exports.decodeJWT = decodeJWT;
exports.getTokenType = getTokenType;
exports.isTokenExpiringSoon = isTokenExpiringSoon;
const jose_1 = require("jose");
const constants_1 = require("../constants");
// Chave secreta para JWT (em produção, usar variável de ambiente)
let JWT_SECRET_KEY = null;
/**
 * Inicializa a chave JWT a partir de um segredo
 * Deve ser chamado uma vez no startup da aplicação
 */
async function initializeJWTSecret(secret) {
    const encoder = new TextEncoder();
    JWT_SECRET_KEY = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
/**
 * Gera token de acesso JWT
 */
async function generateAccessToken(options) {
    if (!JWT_SECRET_KEY) {
        throw new Error('JWT secret não inicializado. Chame initializeJWTSecret primeiro.');
    }
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        sub: options.userId,
        sid: options.sessionId,
        typ: 'access',
        iat: now,
        exp: now + constants_1.AUTH_CONSTANTS.ACCESS_TOKEN_EXPIRY,
        iss: constants_1.AUTH_CONSTANTS.JWT_ISSUER,
        aud: constants_1.AUTH_CONSTANTS.JWT_AUDIENCE,
        mfa: options.mfaVerified,
    };
    return new jose_1.SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuedAt()
        .setExpirationTime(`${constants_1.AUTH_CONSTANTS.ACCESS_TOKEN_EXPIRY}s`)
        .setIssuer(constants_1.AUTH_CONSTANTS.JWT_ISSUER)
        .setAudience(constants_1.AUTH_CONSTANTS.JWT_AUDIENCE)
        .sign(JWT_SECRET_KEY);
}
/**
 * Gera refresh token JWT
 */
async function generateRefreshToken(options) {
    if (!JWT_SECRET_KEY) {
        throw new Error('JWT secret não inicializado. Chame initializeJWTSecret primeiro.');
    }
    const now = Math.floor(Date.now() / 1000);
    const counter = options.counter ?? 0;
    const payload = {
        sub: options.userId,
        sid: options.sessionId,
        typ: 'refresh',
        iat: now,
        exp: now + constants_1.AUTH_CONSTANTS.REFRESH_TOKEN_EXPIRY,
        iss: constants_1.AUTH_CONSTANTS.JWT_ISSUER,
        aud: constants_1.AUTH_CONSTANTS.JWT_AUDIENCE,
        counter,
    };
    return new jose_1.SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuedAt()
        .setExpirationTime(`${constants_1.AUTH_CONSTANTS.REFRESH_TOKEN_EXPIRY}s`)
        .setIssuer(constants_1.AUTH_CONSTANTS.JWT_ISSUER)
        .setAudience(constants_1.AUTH_CONSTANTS.JWT_AUDIENCE)
        .sign(JWT_SECRET_KEY);
}
/**
 * Gera ambos os tokens (access + refresh)
 */
async function generateAuthTokens(options) {
    const [accessToken, refreshToken] = await Promise.all([
        generateAccessToken(options),
        generateRefreshToken(options),
    ]);
    return {
        accessToken,
        refreshToken,
        expiresAt: new Date(Date.now() + constants_1.AUTH_CONSTANTS.ACCESS_TOKEN_EXPIRY * 1000),
        refreshExpiresAt: new Date(Date.now() + constants_1.AUTH_CONSTANTS.REFRESH_TOKEN_EXPIRY * 1000),
    };
}
/**
 * Verifica e decodifica token JWT
 * Retorna o payload se válido, ou erro se inválido/expirado
 */
async function verifyJWT(token) {
    if (!JWT_SECRET_KEY) {
        return {
            valid: false,
            error: { code: 'INTERNAL_ERROR', message: 'Configuração de autenticação inválida' },
        };
    }
    try {
        const { payload } = await (0, jose_1.jwtVerify)(token, JWT_SECRET_KEY, {
            issuer: constants_1.AUTH_CONSTANTS.JWT_ISSUER,
            audience: constants_1.AUTH_CONSTANTS.JWT_AUDIENCE,
        });
        // Type assertion segura após verificação
        return { valid: true, payload: payload };
    }
    catch (error) {
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
function decodeJWT(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            return null;
        }
        const payload = parts[1];
        const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
        return JSON.parse(decoded);
    }
    catch {
        return null;
    }
}
/**
 * Extrai tipo do token (access ou refresh)
 */
function getTokenType(token) {
    const decoded = decodeJWT(token);
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
function isTokenExpiringSoon(token) {
    const decoded = decodeJWT(token);
    if (!decoded?.exp) {
        return false;
    }
    const now = Math.floor(Date.now() / 1000);
    const timeUntilExpiry = decoded.exp - now;
    // Menos de 2 minutos
    return timeUntilExpiry < 120;
}
//# sourceMappingURL=tokens.js.map
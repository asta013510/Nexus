/**
 * Utils de Geração e Verificação de Tokens JWT
 *
 * Usa biblioteca 'jose' para operações JWT seguras
 */
import type { JWTPayload, RefreshTokenPayload, TokenOptions, AuthError } from '../types';
/**
 * Inicializa a chave JWT a partir de um segredo
 * Deve ser chamado uma vez no startup da aplicação
 */
export declare function initializeJWTSecret(secret: string): Promise<void>;
/**
 * Gera token de acesso JWT
 */
export declare function generateAccessToken(options: TokenOptions): Promise<string>;
/**
 * Gera refresh token JWT
 */
export declare function generateRefreshToken(options: TokenOptions): Promise<string>;
/**
 * Gera ambos os tokens (access + refresh)
 */
export declare function generateAuthTokens(options: TokenOptions): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresAt: Date;
    refreshExpiresAt: Date;
}>;
/**
 * Verifica e decodifica token JWT
 * Retorna o payload se válido, ou erro se inválido/expirado
 */
export declare function verifyJWT<T extends JWTPayload | RefreshTokenPayload>(token: string): Promise<{
    valid: true;
    payload: T;
} | {
    valid: false;
    error: AuthError;
}>;
/**
 * Decodifica token sem verificar assinatura (apenas para debugging/logging)
 * NUNCA use isso para decisões de segurança!
 */
export declare function decodeJWT<T>(token: string): T | null;
/**
 * Extrai tipo do token (access ou refresh)
 */
export declare function getTokenType(token: string): 'access' | 'refresh' | 'unknown';
/**
 * Verifica se token está próximo de expirar (menos de 2 minutos)
 */
export declare function isTokenExpiringSoon(token: string): boolean;
//# sourceMappingURL=tokens.d.ts.map
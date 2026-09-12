/**
 * @zero/crypto - Operações JWT
 *
 * SECURITY:
 * - Usar apenas algoritmos seguros (RS256, ES256)
 * - Validar issuer, audience, expiration
 * - NUNCA usar HS256 em produção sem segredo forte
 */
import type { JWTPayload as JoseJWTPayload } from 'jose';
export interface JWTPayload extends JoseJWTPayload {
    userId: string;
    sessionId: string;
    deviceId?: string;
    email?: string;
}
export interface RefreshTokenPayload {
    userId: string;
    sessionId: string;
    deviceId: string;
    jti: string;
}
interface JWTResult {
    valid: boolean;
    payload?: JWTPayload | RefreshTokenPayload;
    error?: string;
}
/**
 * Gera um access token JWT
 */
export declare function generateAccessToken(payload: {
    userId: string;
    sessionId: string;
    deviceId?: string;
    email?: string;
}, expirySeconds?: number): Promise<string>;
/**
 * Gera um refresh token JWT
 */
export declare function generateRefreshToken(payload: {
    userId: string;
    sessionId: string;
    deviceId: string;
}, expirySeconds?: number): Promise<string>;
/**
 * Verifica e valida um token JWT
 */
export declare function verifyJWT(token: string): Promise<JWTResult>;
/**
 * Decodifica um token JWT sem validar assinatura (apenas para debugging/logging)
 * SECURITY: NUNCA usar este resultado para autorização
 */
export declare function decodeJWT(token: string): {
    payload: any;
    header: any;
} | null;
declare const _default: {
    generateAccessToken: typeof generateAccessToken;
    generateRefreshToken: typeof generateRefreshToken;
    verifyJWT: typeof verifyJWT;
    decodeJWT: typeof decodeJWT;
};
export default _default;
//# sourceMappingURL=jwt.d.ts.map
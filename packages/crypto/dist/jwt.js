/**
 * @zero/crypto - Operações JWT
 *
 * SECURITY:
 * - Usar apenas algoritmos seguros (RS256, ES256)
 * - Validar issuer, audience, expiration
 * - NUNCA usar HS256 em produção sem segredo forte
 */
import { SignJWT, jwtVerify } from 'jose';
let keyCache = null;
async function getSigningKey() {
    if (!keyCache) {
        const secret = process.env.JWT_SECRET || 'fallback-dev-secret-change-in-production';
        const encoder = new TextEncoder();
        keyCache = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    }
    return keyCache;
}
/**
 * Gera um access token JWT
 */
export async function generateAccessToken(payload, expirySeconds = 900) {
    const secret = process.env.JWT_SECRET || 'fallback-dev-secret-change-in-production';
    return new SignJWT({
        userId: payload.userId,
        sessionId: payload.sessionId,
        deviceId: payload.deviceId,
        email: payload.email,
    })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setIssuer('zero-security')
        .setAudience('zero-app')
        .setExpirationTime(`${expirySeconds}s`)
        .setJti(payload.sessionId)
        .sign(new TextEncoder().encode(secret));
}
/**
 * Gera um refresh token JWT
 */
export async function generateRefreshToken(payload, expirySeconds = 604800) {
    const secret = process.env.JWT_SECRET || 'fallback-dev-secret-change-in-production';
    const jti = crypto.randomUUID();
    return new SignJWT({
        userId: payload.userId,
        sessionId: payload.sessionId,
        deviceId: payload.deviceId,
    })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setIssuer('zero-security')
        .setAudience('zero-app')
        .setExpirationTime(`${expirySeconds}s`)
        .setJti(jti)
        .sign(new TextEncoder().encode(secret));
}
/**
 * Verifica e valida um token JWT
 */
export async function verifyJWT(token) {
    try {
        const secret = process.env.JWT_SECRET || 'fallback-dev-secret-change-in-production';
        const { payload } = await jwtVerify(token, new TextEncoder().encode(secret), {
            issuer: 'zero-security',
            audience: 'zero-app',
        });
        return {
            valid: true,
            payload: payload,
        };
    }
    catch (error) {
        if (error.name === 'JWTExpired') {
            return { valid: false, error: 'Token expirado' };
        }
        if (error.name === 'JOSEError') {
            return { valid: false, error: 'Token inválido' };
        }
        return { valid: false, error: 'Erro ao verificar token' };
    }
}
/**
 * Decodifica um token JWT sem validar assinatura (apenas para debugging/logging)
 * SECURITY: NUNCA usar este resultado para autorização
 */
export function decodeJWT(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            return null;
        }
        const header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf-8'));
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'));
        return { header, payload };
    }
    catch {
        return null;
    }
}
export default {
    generateAccessToken,
    generateRefreshToken,
    verifyJWT,
    decodeJWT,
};
//# sourceMappingURL=jwt.js.map
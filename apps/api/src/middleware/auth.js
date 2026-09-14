/**
 * Middleware de Autenticação
 *
 * RESPONSABILIDADES:
 * - Validar JWT access token
 * - Extrair sessão do request
 * - Proteger rotas que exigem autenticação
 * - Renovar tokens quando necessário
 */
import { verifyJWT } from '@zero/auth';
/**
 * Extrai sessão do request (JWT ou cookie)
 */
export function getSessionFromRequest(req) {
    // Tentar extrair do header Authorization
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        try {
            const payload = verifyJWT(token, 'access');
            return {
                userId: payload.userId,
                sessionId: payload.sessionId,
                deviceId: payload.deviceId,
                createdAt: new Date(payload.iat * 1000),
            };
        }
        catch {
            // Token inválido
        }
    }
    // Tentar extrair do cookie
    const accessToken = req.cookies?.accessToken;
    if (accessToken) {
        try {
            const payload = verifyJWT(accessToken, 'access');
            return {
                userId: payload.userId,
                sessionId: payload.sessionId,
                deviceId: payload.deviceId,
                createdAt: new Date(payload.iat * 1000),
            };
        }
        catch {
            // Token inválido
        }
    }
    return null;
}
/**
 * Middleware que exige autenticação
 * Adiciona auth ao request se válido
 */
export function requireAuth(req, res, next) {
    const session = getSessionFromRequest(req);
    if (!session) {
        res.status(401).json({
            error: 'Unauthorized',
            message: 'Autenticação necessária',
        });
        return;
    }
    // Adicionar informações de auth ao request
    req.auth = session;
    next();
}
/**
 * Middleware para operações sensíveis (step-up auth)
 * Pode exigir re-autenticação recente
 */
export function requireRecentAuth(maxAgeMs = 5 * 60 * 1000) {
    return (req, res, next) => {
        const session = getSessionFromRequest(req);
        if (!session) {
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Autenticação necessária',
            });
            return;
        }
        // Verificar se a sessão é recente o suficiente
        const now = Date.now();
        const sessionAge = now - session.createdAt.getTime();
        if (sessionAge > maxAgeMs) {
            res.status(403).json({
                error: 'Authentication Required',
                message: 'Re-autenticação necessária para esta operação',
                requiresStepUp: true,
            });
            return;
        }
        req.auth = session;
        next();
    };
}
/**
 * Middleware opcional de autenticação
 * Adiciona auth se presente, mas não falha se ausente
 */
export function optionalAuth(req, res, next) {
    const session = getSessionFromRequest(req);
    if (session) {
        req.auth = session;
    }
    next();
}
//# sourceMappingURL=auth.js.map
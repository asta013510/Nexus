/**
 * Rotas de Autenticação
 *
 * ENDPOINTS:
 * POST   /api/auth/register     - Registro de usuário
 * POST   /api/auth/login        - Login (senha + email)
 * POST   /api/auth/mfa/verify   - Verificação MFA
 * POST   /api/auth/refresh      - Refresh token
 * POST   /api/auth/logout       - Logout
 * POST   /api/auth/logout-all   - Logout de todos dispositivos
 * GET    /api/auth/me           - Dados do usuário atual
 *
 * SECURITY:
 * - Rate limiting específico para login
 * - Timing-safe comparison para senhas
 * - Audit logging de todas as tentativas
 * - Headers de segurança
 * - Validação rigorosa de input
 */
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { AuthService } from '@zero/auth';
import { getSessionFromRequest } from '../middleware/auth.js';
const router = Router();
// Rate limiting agressivo para login (prevenir brute force)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // 5 tentativas por janela
    message: {
        error: 'Too many login attempts',
        message: 'Muitas tentativas de login. Tente novamente em 15 minutos.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        // Usar IP + User Agent para identificar cliente
        const ip = req.ip || req.socket.remoteAddress || 'unknown';
        const ua = req.get('user-agent') || 'unknown';
        return `${ip}:${ua}`;
    },
    handler: async (req, res) => {
        // Log de tentativa de rate limit bypass (potencial ataque)
        console.warn('Login rate limit exceeded:', {
            ip: req.ip,
            userAgent: req.get('user-agent'),
            timestamp: new Date().toISOString(),
        });
        res.status(429).json({
            error: 'Too many login attempts',
            message: 'Muitas tentativas de login. Tente novamente em 15 minutos.',
        });
    },
});
/**
 * POST /api/auth/register
 * Registro de novo usuário
 */
router.post('/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        // Validar presença dos campos
        if (!email || !password || !name) {
            res.status(400).json({
                error: 'Bad Request',
                message: 'Email, password e name são obrigatórios',
            });
            return;
        }
        // Registrar usuário
        const result = await AuthService.register({
            email,
            password,
            name,
        });
        // Sucesso - retornar dados sem senha
        res.status(201).json({
            success: true,
            message: 'Usuário registrado com sucesso. Configure o MFA para continuar.',
            data: {
                userId: result.userId,
                email: result.email,
                name: result.name,
                mfaRequired: true,
                mfaSecret: result.mfaSecret,
                mfaQrCode: result.mfaQrCode,
                recoveryCodes: result.recoveryCodes,
            },
        });
    }
    catch (error) {
        console.error('Registration error:', error);
        // Mapear erros conhecidos
        if (error.code === 'EMAIL_EXISTS') {
            res.status(409).json({
                error: 'Conflict',
                message: 'Email já cadastrado',
            });
            return;
        }
        if (error.code === 'INVALID_EMAIL' || error.code === 'WEAK_PASSWORD') {
            res.status(400).json({
                error: 'Bad Request',
                message: error.message,
            });
            return;
        }
        // Erro genérico (não expor detalhes)
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Erro ao registrar usuário',
        });
    }
});
/**
 * POST /api/auth/login
 * Login com email e senha
 * Retorna necessidade de MFA se configurado
 */
router.post('/login', loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        // Validar presença
        if (!email || !password) {
            res.status(400).json({
                error: 'Bad Request',
                message: 'Email e password são obrigatórios',
            });
            return;
        }
        // Tentar login
        const result = await AuthService.login({
            email,
            password,
            ipAddress: req.ip || req.socket.remoteAddress || '',
            userAgent: req.get('user-agent') || '',
        });
        // Caso 1: Login bem-sucedido, MFA não necessário
        if (result.status === 'authenticated') {
            // Setar cookies seguros
            res.cookie('accessToken', result.tokens.accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 15 * 60 * 1000, // 15 minutos
                path: '/api',
            });
            res.cookie('refreshToken', result.tokens.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 dias
                path: '/api/auth/refresh',
            });
            res.json({
                success: true,
                status: 'authenticated',
                data: {
                    user: result.user,
                    requiresMfa: false,
                },
            });
            return;
        }
        // Caso 2: MFA necessário
        if (result.status === 'mfa_required') {
            res.json({
                success: true,
                status: 'mfa_required',
                data: {
                    mfaSessionId: result.mfaSessionId,
                    mfaType: result.mfaType,
                    userId: result.userId,
                },
            });
            return;
        }
        // Caso 3: Conta bloqueada
        if (result.status === 'locked') {
            res.status(423).json({
                error: 'Account Locked',
                message: 'Conta temporariamente bloqueada devido a múltiplas tentativas falhas.',
                lockedUntil: result.lockedUntil,
            });
            return;
        }
        // Should not reach here
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Estado inesperado',
        });
    }
    catch (error) {
        console.error('Login error:', error);
        if (error.code === 'INVALID_CREDENTIALS') {
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Email ou senha inválidos',
            });
            return;
        }
        if (error.code === 'ACCOUNT_LOCKED') {
            res.status(423).json({
                error: 'Account Locked',
                message: 'Conta temporariamente bloqueada',
                lockedUntil: error.lockedUntil,
            });
            return;
        }
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Erro ao fazer login',
        });
    }
});
/**
 * POST /api/auth/mfa/verify
 * Verificar código MFA (TOTP ou recovery code)
 */
router.post('/mfa/verify', async (req, res) => {
    try {
        const { mfaSessionId, code, type = 'totp' } = req.body;
        if (!mfaSessionId || !code) {
            res.status(400).json({
                error: 'Bad Request',
                message: 'mfaSessionId e code são obrigatórios',
            });
            return;
        }
        const result = await AuthService.verifyMFA({
            mfaSessionId,
            code,
            type,
            ipAddress: req.ip || req.socket.remoteAddress || '',
            userAgent: req.get('user-agent') || '',
        });
        if (result.success) {
            // Setar cookies
            res.cookie('accessToken', result.tokens.accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 15 * 60 * 1000,
                path: '/api',
            });
            res.cookie('refreshToken', result.tokens.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000,
                path: '/api/auth/refresh',
            });
            res.json({
                success: true,
                status: 'authenticated',
                data: {
                    user: result.user,
                    requiresMfa: false,
                },
            });
            return;
        }
        else {
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Código MFA inválido',
                attemptsRemaining: result.attemptsRemaining,
            });
        }
    }
    catch (error) {
        console.error('MFA verification error:', error);
        if (error.code === 'INVALID_MFA_CODE') {
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Código MFA inválido',
                attemptsRemaining: error.attemptsRemaining,
            });
            return;
        }
        if (error.code === 'MFA_SESSION_EXPIRED') {
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Sessão MFA expirada. Faça login novamente.',
            });
            return;
        }
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Erro na verificação MFA',
        });
    }
});
/**
 * POST /api/auth/refresh
 * Refresh token para obter novo access token
 */
router.post('/refresh', async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken;
        if (!refreshToken) {
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Refresh token não encontrado',
            });
            return;
        }
        const result = await AuthService.refreshAccessToken(refreshToken);
        if (result.success) {
            res.cookie('accessToken', result.accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 15 * 60 * 1000,
                path: '/api',
            });
            res.json({
                success: true,
                data: {
                    accessToken: result.accessToken,
                },
            });
            return;
        }
        res.status(401).json({
            error: 'Unauthorized',
            message: 'Refresh token inválido ou expirado',
        });
    }
    catch (error) {
        console.error('Token refresh error:', error);
        res.status(401).json({
            error: 'Unauthorized',
            message: 'Falha ao renovar token',
        });
    }
});
/**
 * POST /api/auth/logout
 * Logout (revoga sessão atual)
 */
router.post('/logout', async (req, res) => {
    try {
        const session = getSessionFromRequest(req);
        const refreshToken = req.cookies?.refreshToken;
        if (session?.sessionId || refreshToken) {
            await AuthService.logout({
                sessionId: session?.sessionId,
                refreshToken,
                ipAddress: req.ip || req.socket.remoteAddress || '',
                userAgent: req.get('user-agent') || '',
            });
        }
        // Limpar cookies
        res.clearCookie('accessToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/api',
        });
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/api/auth/refresh',
        });
        res.json({
            success: true,
            message: 'Logout realizado com sucesso',
        });
    }
    catch (error) {
        console.error('Logout error:', error);
        // Mesmo com erro, limpar cookies
        res.clearCookie('accessToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/api',
        });
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/api/auth/refresh',
        });
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Erro ao fazer logout',
        });
    }
});
/**
 * POST /api/auth/logout-all
 * Logout de todos os dispositivos (revoga todas as sessões)
 */
router.post('/logout-all', async (req, res) => {
    try {
        const session = getSessionFromRequest(req);
        if (!session?.userId) {
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Usuário não autenticado',
            });
            return;
        }
        await AuthService.logoutAll({
            userId: session.userId,
            ipAddress: req.ip || req.socket.remoteAddress || '',
            userAgent: req.get('user-agent') || '',
        });
        // Limpar cookies
        res.clearCookie('accessToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/api',
        });
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/api/auth/refresh',
        });
        res.json({
            success: true,
            message: 'Todos os dispositivos foram desconectados',
        });
    }
    catch (error) {
        console.error('Logout all error:', error);
        res.clearCookie('accessToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/api',
        });
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/api/auth/refresh',
        });
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Erro ao desconectar todos os dispositivos',
        });
    }
});
/**
 * GET /api/auth/me
 * Dados do usuário autenticado atual
 */
router.get('/me', async (req, res) => {
    try {
        const session = getSessionFromRequest(req);
        if (!session?.userId) {
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Usuário não autenticado',
            });
            return;
        }
        const user = await AuthService.getUserById(session.userId);
        if (!user) {
            res.status(404).json({
                error: 'Not Found',
                message: 'Usuário não encontrado',
            });
            return;
        }
        res.json({
            success: true,
            data: {
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    mfaEnabled: user.mfaEnabled,
                    webauthnEnabled: user.webauthnEnabled,
                    createdAt: user.createdAt,
                },
                session: {
                    sessionId: session.sessionId,
                    deviceId: session.deviceId,
                    createdAt: session.createdAt,
                },
            },
        });
    }
    catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Erro ao buscar dados do usuário',
        });
    }
});
export { router as authRoutes };
//# sourceMappingURL=auth.js.map
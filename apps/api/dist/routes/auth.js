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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9yb3V0ZXMvYXV0aC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7Ozs7Ozs7Ozs7Ozs7O0dBa0JHO0FBRUgsT0FBTyxFQUFFLE1BQU0sRUFBbUMsTUFBTSxTQUFTLENBQUM7QUFDbEUsT0FBTyxTQUFTLE1BQU0sb0JBQW9CLENBQUM7QUFDM0MsT0FBTyxFQUFFLFdBQVcsRUFBRSxNQUFNLFlBQVksQ0FBQztBQUN6QyxPQUFPLEVBQUUscUJBQXFCLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQztBQUU5RCxNQUFNLE1BQU0sR0FBRyxNQUFNLEVBQUUsQ0FBQztBQUV4Qiw0REFBNEQ7QUFDNUQsTUFBTSxZQUFZLEdBQUcsU0FBUyxDQUFDO0lBQzdCLFFBQVEsRUFBRSxFQUFFLEdBQUcsRUFBRSxHQUFHLElBQUksRUFBRSxhQUFhO0lBQ3ZDLEdBQUcsRUFBRSxDQUFDLEVBQUUsMEJBQTBCO0lBQ2xDLE9BQU8sRUFBRTtRQUNQLEtBQUssRUFBRSx5QkFBeUI7UUFDaEMsT0FBTyxFQUFFLDREQUE0RDtLQUN0RTtJQUNELGVBQWUsRUFBRSxJQUFJO0lBQ3JCLGFBQWEsRUFBRSxLQUFLO0lBQ3BCLFlBQVksRUFBRSxDQUFDLEdBQUcsRUFBRSxFQUFFO1FBQ3BCLGdEQUFnRDtRQUNoRCxNQUFNLEVBQUUsR0FBRyxHQUFHLENBQUMsRUFBRSxJQUFJLEdBQUcsQ0FBQyxNQUFNLENBQUMsYUFBYSxJQUFJLFNBQVMsQ0FBQztRQUMzRCxNQUFNLEVBQUUsR0FBRyxHQUFHLENBQUMsR0FBRyxDQUFDLFlBQVksQ0FBQyxJQUFJLFNBQVMsQ0FBQztRQUM5QyxPQUFPLEdBQUcsRUFBRSxJQUFJLEVBQUUsRUFBRSxDQUFDO0lBQ3ZCLENBQUM7SUFDRCxPQUFPLEVBQUUsS0FBSyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsRUFBRTtRQUMxQiwyREFBMkQ7UUFDM0QsT0FBTyxDQUFDLElBQUks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T0FBTyxFQUFFLGlDQUFpQztTQUMzQyxDQUFDLENBQUM7SUFDTCxDQUFDO0FBQ0gsQ0FBQyxDQUFDLENBQUM7QUFFSCxPQUFPLEVBQUUsTUFBTSxJQUFJLFVBQVUsRUFBRSxDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBSb3RhcyBkZSBBdXRlbnRpY2HDp8Ojb1xuICogXG4gKiBFTkRQT0lOVFM6XG4gKiBQT1NUICAgL2FwaS9hdXRoL3JlZ2lzdGVyICAgICAtIFJlZ2lzdHJvIGRlIHVzdcOhcmlvXG4gKiBQT1NUICAgL2FwaS9hdXRoL2xvZ2luICAgICAgICAtIExvZ2luIChzZW5oYSArIGVtYWlsKVxuICogUE9TVCAgIC9hcGkvYXV0aC9tZmEvdmVyaWZ5ICAgLSBWZXJpZmljYcOnw6NvIE1GQVxuICogUE9TVCAgIC9hcGkvYXV0aC9yZWZyZXNoICAgICAgLSBSZWZyZXNoIHRva2VuXG4gKiBQT1NUICAgL2FwaS9hdXRoL2xvZ291dCAgICAgICAtIExvZ291dFxuICogUE9TVCAgIC9hcGkvYXV0aC9sb2dvdXQtYWxsICAgLSBMb2dvdXQgZGUgdG9kb3MgZGlzcG9zaXRpdm9zXG4gKiBHRVQgICAgL2FwaS9hdXRoL21lICAgICAgICAgICAtIERhZG9zIGRvIHVzdcOhcmlvIGF0dWFsXG4gKiBcbiAqIFNFQ1VSSVRZOlxuICogLSBSYXRlIGxpbWl0aW5nIGVzcGVjw61maWNvIHBhcmEgbG9naW5cbiAqIC0gVGltaW5nLXNhZmUgY29tcGFyaXNvbiBwYXJhIHNlbmhhc1xuICogLSBBdWRpdCBsb2dnaW5nIGRlIHRvZGFzIGFzIHRlbnRhdGl2YXNcbiAqIC0gSGVhZGVycyBkZSBzZWd1cmFuw6dhXG4gKiAtIFZhbGlkYcOnw6NvIHJpZ29yb3NhIGRlIGlucHV0XG4gKi9cblxuaW1wb3J0IHsgUm91dGVyLCBSZXF1ZXN0LCBSZXNwb25zZSwgTmV4dEZ1bmN0aW9uIH0gZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgcmF0ZUxpbWl0IGZyb20gJ2V4cHJlc3MtcmF0ZS1saW1pdCc7XG5pbXBvcnQgeyBBdXRoU2VydmljZSB9IGZyb20gJ0B6ZXJvL2F1dGgnO1xuaW1wb3J0IHsgZ2V0U2Vzc2lvbkZyb21SZXF1ZXN0IH0gZnJvbSAnLi4vbWlkZGxld2FyZS9hdXRoLmpzJztcblxuY29uc3Qgcm91dGVyID0gUm91dGVyKCk7XG5cbi8vIFJhdGUgbGltaXRpbmcgYWdyZXNzaXZvIHBhcmEgbG9naW4gKHByZXZlbmlyIGJydXRlIGZvcmNlKVxuY29uc3QgbG9naW5MaW1pdGVyID0gcmF0ZUxpbWl0KHtcbiAgd2luZG93TXM6IDE1ICogNjAgKiAxMDAwLCAvLyAxNSBtaW51dG9zXG4gIG1heDogNSwgLy8gNSB0ZW50YXRpdmFzIHBvciBqYW5lbGFcbiAgbWVzc2FnZToge1xuICAgIGVycm9yOiAnVG9vIG1hbnkgbG9naW4gYXR0ZW1wdHMnLFxuICAgIG1lc3NhZ2U6ICdNdWl0YXMgdGVudGF0aXZhcyBkZSBsb2dpbi4gVGVudGUgbm92YW1lbnRlIGVtIDE1IG1pbnV0b3MuJyxcbiAgfSxcbiAgc3RhbmRhcmRIZWFkZXJzOiB0cnVlLFxuICBsZWdhY3lIZWFkZXJzOiBmYWxzZSxcbiAga2V5R2VuZXJhdG9yOiAocmVxKSA9PiB7XG4gICAgLy8gVXNhciBJUCArIFVzZXIgQWdlbnQgcGFyYSBpZGVudGlmaWNhciBjbGllbnRlXG4gICAgY29uc3QgaXAgPSByZXEuaXAgfHwgcmVxLnNvY2tldC5yZW1vdGVBZGRyZXNzIHx8ICd1bmtub3duJztcbiAgICBjb25zdCB1YSA9IHJlcS5nZXQoJ3VzZXItYWdlbnQnKSB8fCAndW5rbm93bic7XG4gICAgcmV0dXJuIGAke2lwfToke3VhfWA7XG4gIH0sXG4gIGhhbmRsZXI6IGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIC8vIExvZyBkZSB0ZW50YXRpdmEgZGUgcmF0ZSBsaW1pdCBieXBhc3MgKHBvdGVuY2lhbCBhdGFxdWUpXG4gICAgY29uc29sZS53YXJuKCdMb2dpbiByYXRlIGxpbWl0IGV4Y2VlZGVkOicsIHtcbiAgICAgIGlwOiByZXEuaXAsXG4gICAgICB1c2VyQWdlbnQ6IHJlcS5nZXQoJ3VzZXItYWdlbnQnKSxcbiAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKS50b0lTT1N0cmluZygpLFxuICAgIH0pO1xuICAgIFxuICAgIHJlcy5zdGF0dXMoNDI5KS5qc29uKHtcbiAgICAgIGVycm9yOiAnVG9vIG1hbnkgbG9naW4gYXR0ZW1wdHMnLFxuICAgICAgbWVzc2FnZTogJ011aXRhcyB0ZW50YXRpdmFzIGRlIGxvZ2luLiBUZW50ZSBub3ZhbWVudGUgZW0gMTUgbWludXRvcy4nLFxuICAgIH0pO1xuICB9LFxufSk7XG5cbi8qKlxuICogUE9TVCAvYXBpL2F1dGgvcmVnaXN0ZXJcbiAqIFJlZ2lzdHJvIGRlIG5vdm8gdXN1w6FyaW9cbiAqL1xucm91dGVyLnBvc3QoJy9yZWdpc3RlcicsIGFzeW5jIChyZXE6IFJlcXVlc3QsIHJlczogUmVzcG9uc2UpID0+IHtcbiAgdHJ5IHtcbiAgICBjb25zdCB7IGVtYWlsLCBwYXNzd29yZCwgbmFtZSB9ID0gcmVxLmJvZHk7XG5cbiAgICAvLyBWYWxpZGFyIHByZXNlbsOnYSBkb3MgY2FtcG9zXG4gICAgaWYgKCFlbWFpbCB8fCAhcGFzc3dvcmQgfHwgIW5hbWUpIHtcbiAgICAgIHJlcy5zdGF0dXMoNDAwKS5qc29uKHtcbiAgICAgICAgZXJyb3I6ICdCYWQgUmVxdWVzdCcsXG4gICAgICAgIG1lc3NhZ2U6ICdFbWFpbCwgcGFzc3dvcmQgZSBuYW1lIHPDo28gb2JyaWdhdMOzcmlvcycsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBSZWdpc3RyYXIgdXN1w6FyaW9cbiAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBBdXRoU2VydmljZS5yZWdpc3Rlcih7XG4gICAgICBlbWFpbCxcbiAgICAgIHBhc3N3b3JkLFxuICAgICAgbmFtZSxcbiAgICB9KTtcblxuICAgIC8vIFN1Y2Vzc28gLSByZXRvcm5hciBkYWRvcyBzZW0gc2VuaGFcbiAgICByZXMuc3RhdHVzKDIwMSkuanNvbih7XG4gICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgbWVzc2FnZTogJ1VzdcOhcmlvIHJlZ2lzdHJhZG8gY29tIHN1Y2Vzc28uIENvbmZpZ3VyZSBvIE1GQSBwYXJhIGNvbnRpbnVhci4nLFxuICAgICAgZGF0YToge1xuICAgICAgICB1c2VySWQ6IHJlc3VsdC51c2VySWQsXG4gICAgICAgIGVtYWlsOiByZXN1bHQuZW1haWwsXG4gICAgICAgIG5hbWU6IHJlc3VsdC5uYW1lLFxuICAgICAgICBtZmFSZXF1aXJlZDogdHJ1ZSxcbiAgICAgICAgbWZhU2VjcmV0OiByZXN1bHQubWZhU2VjcmV0LFxuICAgICAgICBtZmFRckNvZGU6IHJlc3VsdC5tZmFRckNvZGUsXG4gICAgICAgIHJlY292ZXJ5Q29kZXM6IHJlc3VsdC5yZWNvdmVyeUNvZGVzLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfSBjYXRjaCAoZXJyb3I6IGFueSkge1xuICAgIGNvbnNvbGUuZXJyb3IoJ1JlZ2lzdHJhdGlvbiBlcnJvcjonLCBlcnJvcik7XG4gICAgXG4gICAgLy8gTWFwZWFyIGVycm9zIGNvbmhlY2lkb3NcbiAgICBpZiAoZXJyb3IuY29kZSA9PT0gJ0VNQUlMX0VYSVNUUycpIHtcbiAgICAgIHJlcy5zdGF0dXMoNDA5KS5qc29uKHtcbiAgICAgICAgZXJyb3I6ICdDb25mbGljdCcsXG4gICAgICAgIG1lc3NhZ2U6ICdFbWFpbCBqw6EgY2FkYXN0cmFkbycsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAoZXJyb3IuY29kZSA9PT0gJ0lOVkFMSURfRU1BSUwnIHx8IGVycm9yLmNvZGUgPT09ICdXRUFLX1BBU1NXT1JEJykge1xuICAgICAgcmVzLnN0YXR1cyg0MDApLmpzb24oe1xuICAgICAgICBlcnJvcjogJ0JhZCBSZXF1ZXN0JyxcbiAgICAgICAgbWVzc2FnZTogZXJyb3IubWVzc2FnZSxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIEVycm8gZ2Vuw6lyaWNvIChuw6NvIGV4cG9yIGRldGFsaGVzKVxuICAgIHJlcy5zdGF0dXMoNTAwKS5qc29uKHtcbiAgICAgIGVycm9yOiAnSW50ZXJuYWwgU2VydmVyIEVycm9yJyxcbiAgICAgIG1lc3NhZ2U6ICdFcnJvIGFvIHJlZ2lzdHJhciB1c3XDoXJpbycsXG4gICAgfSk7XG4gIH1cbn0pO1xuXG4vKipcbiAqIFBPU1QgL2FwaS9hdXRoL2xvZ2luXG4gKiBMb2dpbiBjb20gZW1haWwgZSBzZW5oYVxuICogUmV0b3JuYSBuZWNlc3NpZGFkZSBkZSBNRkEgc2UgY29uZmlndXJhZG9cbiAqL1xucm91dGVyLnBvc3QoJy9sb2dpbicsIGxvZ2luTGltaXRlciwgYXN5bmMgKHJlcTogUmVxdWVzdCwgcmVzOiBSZXNwb25zZSkgPT4ge1xuICB0cnkge1xuICAgIGNvbnN0IHsgZW1haWwsIHBhc3N3b3JkIH0gPSByZXEuYm9keTtcblxuICAgIC8vIFZhbGlkYXIgcHJlc2Vuw6dhXG4gICAgaWYgKCFlbWFpbCB8fCAhcGFzc3dvcmQpIHtcbiAgICAgIHJlcy5zdGF0dXMoNDAwKS5qc29uKHtcbiAgICAgICAgZXJyb3I6ICdCYWQgUmVxdWVzdCcsXG4gICAgICAgIG1lc3NhZ2U6ICdFbWFpbCBlIHBhc3N3b3JkIHPDo28gb2JyaWdhdMOzcmlvcycsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBUZW50YXIgbG9naW5cbiAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBBdXRoU2VydmljZS5sb2dpbih7XG4gICAgICBlbWFpbCxcbiAgICAgIHBhc3N3b3JkLFxuICAgICAgaXBBZGRyZXNzOiByZXEuaXAgfHwgcmVxLnNvY2tldC5yZW1vdGVBZGRyZXNzIHx8ICcnLFxuICAgICAgdXNlckFnZW50OiByZXEuZ2V0KCd1c2VyLWFnZW50JykgfHwgJycsXG4gICAgfSk7XG5cbiAgICAvLyBDYXNvIDE6IExvZ2luIGJlbS1zdWNlZGlkbywgTUZBIG7Do28gbmVjZXNzw6FyaW9cbiAgICBpZiAocmVzdWx0LnN0YXR1cyA9PT0gJ2F1dGhlbnRpY2F0ZWQnKSB7XG4gICAgICAvLyBTZXRhciBjb29raWVzIHNlZ3Vyb3NcbiAgICAgIHJlcy5jb29raWUoJ2FjY2Vzc1Rva2VuJywgcmVzdWx0LnRva2Vucy5hY2Nlc3NUb2tlbiwge1xuICAgICAgICBodHRwT25seTogdHJ1ZSxcbiAgICAgICAgc2VjdXJlOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nLFxuICAgICAgICBzYW1lU2l0ZTogJ3N0cmljdCcsXG4gICAgICAgIG1heEFnZTogMTUgKiA2MCAqIDEwMDAsIC8vIDE1IG1pbnV0b3NcbiAgICAgICAgcGF0aDogJy9hcGknLFxuICAgICAgfSk7XG5cbiAgICAgIHJlcy5jb29raWUoJ3JlZnJlc2hUb2tlbicsIHJlc3VsdC50b2tlbnMucmVmcmVzaFRva2VuLCB7XG4gICAgICAgIGh0dHBPbmx5OiB0cnVlLFxuICAgICAgICBzZWN1cmU6IHByb2Nlc3MuZW52Lk5PREVfRU5WID09PSAncHJvZHVjdGlvbicsXG4gICAgICAgIHNhbWVTaXRlOiAnc3RyaWN0JyxcbiAgICAgICAgbWF4QWdlOiA3ICogMjQgKiA2MCAqIDYwICogMTAwMCwgLy8gNyBkaWFzXG4gICAgICAgIHBhdGg6ICcvYXBpL2F1dGgvcmVmcmVzaCcsXG4gICAgICB9KTtcblxuICAgICAgcmVzLmpzb24oe1xuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICBzdGF0dXM6ICdhdXRoZW50aWNhdGVkJyxcbiAgICAgICAgZGF0YToge1xuICAgICAgICAgIHVzZXI6IHJlc3VsdC51c2VyLFxuICAgICAgICAgIHJlcXVpcmVzTWZhOiBmYWxzZSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIENhc28gMjogTUZBIG5lY2Vzc8OhcmlvXG4gICAgaWYgKHJlc3VsdC5zdGF0dXMgPT09ICdtZmFfcmVxdWlyZWQnKSB7XG4gICAgICByZXMuanNvbih7XG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgIHN0YXR1czogJ21mYV9yZXF1aXJlZCcsXG4gICAgICAgIGRhdGE6IHtcbiAgICAgICAgICBtZmFTZXNzaW9uSWQ6IHJlc3VsdC5tZmFTZXNzaW9uSWQsXG4gICAgICAgICAgbWZhVHlwZTogcmVzdWx0Lm1mYVR5cGUsXG4gICAgICAgICAgdXNlcklkOiByZXN1bHQudXNlcklkLFxuICAgICAgICB9LFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQ2FzbyAzOiBDb250YSBibG9xdWVhZGFcbiAgICBpZiAocmVzdWx0LnN0YXR1cyA9PT0gJ2xvY2tlZCcpIHtcbiAgICAgIHJlcy5zdGF0dXMoNDIzKS5qc29uKHtcbiAgICAgICAgZXJyb3I6ICdBY2NvdW50IExvY2tlZCcsXG4gICAgICAgIG1lc3NhZ2U6ICdDb250YSB0ZW1wb3JhcmlhbWVudGUgYmxvcXVlYWRhIGRldmlkbyBhIG3Dumx0aXBsYXMgdGVudGF0aXZhcyBmYWxoYXMuJyxcbiAgICAgICAgbG9ja2VkVW50aWw6IHJlc3VsdC5sb2NrZWRVbnRpbCxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIFNob3VsZCBub3QgcmVhY2ggaGVyZVxuICAgIHJlcy5zdGF0dXMoNTAwKS5qc29uKHtcbiAgICAgIGVycm9yOiAnSW50ZXJuYWwgU2VydmVyIEVycm9yJyxcbiAgICAgIG1lc3NhZ2U6ICdFc3RhZG8gaW5lc3BlcmFkbycsXG4gICAgfSk7XG4gIH0gY2F0Y2ggKGVycm9yOiBhbnkpIHtcbiAgICBjb25zb2xlLmVycm9yKCdMb2dpbiBlcnJvcjonLCBlcnJvcik7XG5cbiAgICBpZiAoZXJyb3IuY29kZSA9PT0gJ0lOVkFMSURfQ1JFREVOVElBTFMnKSB7XG4gICAgICByZXMuc3RhdHVzKDQwMSkuanNvbih7XG4gICAgICAgIGVycm9yOiAnVW5hdXRob3JpemVkJyxcbiAgICAgICAgbWVzc2FnZTogJ0VtYWlsIG91IHNlbmhhIGludsOhbGlkb3MnLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgaWYgKGVycm9yLmNvZGUgPT09ICdBQ0NPVU5UX0xPQ0tFRCcpIHtcbiAgICAgIHJlcy5zdGF0dXMoNDIzKS5qc29uKHtcbiAgICAgICAgZXJyb3I6ICdBY2NvdW50IExvY2tlZCcsXG4gICAgICAgIG1lc3NhZ2U6ICdDb250YSB0ZW1wb3JhcmlhbWVudGUgYmxvcXVlYWRhJyxcbiAgICAgICAgbG9ja2VkVW50aWw6IGVycm9yLmxvY2tlZFVudGlsLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgcmVzLnN0YXR1cyg1MDApLmpzb24oe1xuICAgICAgZXJyb3I6ICdJbnRlcm5hbCBTZXJ2ZXIgRXJyb3InLFxuICAgICAgbWVzc2FnZTogJ0Vycm8gYW8gZmF6ZXIgbG9naW4nLFxuICAgIH0pO1xuICB9XG59KTtcblxuLyoqXG4gKiBQT1NUIC9hcGkvYXV0aC9tZmEvdmVyaWZ5XG4gKiBWZXJpZmljYXIgY8OzZGlnbyBNRkEgKFRPVFAgb3UgcmVjb3ZlcnkgY29kZSlcbiAqL1xucm91dGVyLnBvc3QoJy9tZmEvdmVyaWZ5JywgYXN5bmMgKHJlcTogUmVxdWVzdCwgcmVzOiBSZXNwb25zZSkgPT4ge1xuICB0cnkge1xuICAgIGNvbnN0IHsgbWZhU2Vzc2lvbklkLCBjb2RlLCB0eXBlID0gJ3RvdHAnIH0gPSByZXEuYm9keTtcblxuICAgIGlmICghbWZhU2Vzc2lvbklkIHx8ICFjb2RlKSB7XG4gICAgICByZXMuc3RhdHVzKDQwMCkuanNvbih7XG4gICAgICAgIGVycm9yOiAnQmFkIFJlcXVlc3QnLFxuICAgICAgICBtZXNzYWdlOiAnbWZhU2Vzc2lvbklkIGUgY29kZSBzw6NvIG9icmlnYXTDs3Jpb3MnLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgQXV0aFNlcnZpY2UudmVyaWZ5TUZBKHtcbiAgICAgIG1mYVNlc3Npb25JZCxcbiAgICAgIGNvZGUsXG4gICAgICB0eXBlLFxuICAgICAgaXBBZGRyZXNzOiByZXEuaXAgfHwgcmVxLnNvY2tldC5yZW1vdGVBZGRyZXNzIHx8ICcnLFxuICAgICAgdXNlckFnZW50OiByZXEuZ2V0KCd1c2VyLWFnZW50JykgfHwgJycsXG4gICAgfSk7XG5cbiAgICBpZiAocmVzdWx0LnN1Y2Nlc3MpIHtcbiAgICAgIC8vIFNldGFyIGNvb2tpZXNcbiAgICAgIHJlcy5jb29raWUoJ2FjY2Vzc1Rva2VuJywgcmVzdWx0LnRva2Vucy5hY2Nlc3NUb2tlbiwge1xuICAgICAgICBodHRwT25seTogdHJ1ZSxcbiAgICAgICAgc2VjdXJlOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nLFxuICAgICAgICBzYW1lU2l0ZTogJ3N0cmljdCcsXG4gICAgICAgIG1heEFnZTogMTUgKiA2MCAqIDEwMDAsXG4gICAgICAgIHBhdGg6ICcvYXBpJyxcbiAgICAgIH0pO1xuXG4gICAgICByZXMuY29va2llKCdyZWZyZXNoVG9rZW4nLCByZXN1bHQudG9rZW5zLnJlZnJlc2hUb2tlbiwge1xuICAgICAgICBodHRwT25seTogdHJ1ZSxcbiAgICAgICAgc2VjdXJlOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nLFxuICAgICAgICBzYW1lU2l0ZTogJ3N0cmljdCcsXG4gICAgICAgIG1heEFnZTogNyAqIDI0ICogNjAgKiA2MCAqIDEwMDAsXG4gICAgICAgIHBhdGg6ICcvYXBpL2F1dGgvcmVmcmVzaCcsXG4gICAgICB9KTtcblxuICAgICAgcmVzLmpzb24oe1xuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICBzdGF0dXM6ICdhdXRoZW50aWNhdGVkJyxcbiAgICAgICAgZGF0YToge1xuICAgICAgICAgIHVzZXI6IHJlc3VsdC51c2VyLFxuICAgICAgICAgIHJlcXVpcmVzTWZhOiBmYWxzZSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXMuc3RhdHVzKDQwMSkuanNvbih7XG4gICAgICAgIGVycm9yOiAnVW5hdXRob3JpemVkJyxcbiAgICAgICAgbWVzc2FnZTogJ0PDs2RpZ28gTUZBIGludsOhbGlkbycsXG4gICAgICAgIGF0dGVtcHRzUmVtYWluaW5nOiByZXN1bHQuYXR0ZW1wdHNSZW1haW5pbmcsXG4gICAgICB9KTtcbiAgICB9XG4gIH0gY2F0Y2ggKGVycm9yOiBhbnkpIHtcbiAgICBjb25zb2xlLmVycm9yKCdNRkEgdmVyaWZpY2F0aW9uIGVycm9yOicsIGVycm9yKTtcblxuICAgIGlmIChlcnJvci5jb2RlID09PSAnSU5WQUxJRF9NRkFfQ09ERScpIHtcbiAgICAgIHJlcy5zdGF0dXMoNDAxKS5qc29uKHtcbiAgICAgICAgZXJyb3I6ICdVbmF1dGhvcml6ZWQnLFxuICAgICAgICBtZXNzYWdlOiAnQ8OzZGlnbyBNRkEgaW52w6FsaWRvJyxcbiAgICAgICAgYXR0ZW1wdHNSZW1haW5pbmc6IGVycm9yLmF0dGVtcHRzUmVtYWluaW5nLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgaWYgKGVycm9yLmNvZGUgPT09ICdNRkFfU0VTU0lPTl9FWFBJUkVEJykge1xuICAgICAgcmVzLnN0YXR1cyg0MDEpLmpzb24oe1xuICAgICAgICBlcnJvcjogJ1VuYXV0aG9yaXplZCcsXG4gICAgICAgIG1lc3NhZ2U6ICdTZXNzw6NvIE1GQSBleHBpcmFkYS4gRmHDp2EgbG9naW4gbm92YW1lbnRlLicsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICByZXMuc3RhdHVzKDUwMCkuanNvbih7XG4gICAgICBlcnJvcjogJ0ludGVybmFsIFNlcnZlciBFcnJvcicsXG4gICAgICBtZXNzYWdlOiAnRXJybyBuYSB2ZXJpZmljYcOnw6NvIE1GQScsXG4gICAgfSk7XG4gIH1cbn0pO1xuXG4vKipcbiAqIFBPU1QgL2FwaS9hdXRoL3JlZnJlc2hcbiAqIFJlZnJlc2ggdG9rZW4gcGFyYSBvYnRlciBub3ZvIGFjY2VzcyB0b2tlblxuICovXG5yb3V0ZXIucG9zdCgnL3JlZnJlc2gnLCBhc3luYyAocmVxOiBSZXF1ZXN0LCByZXM6IFJlc3BvbnNlKSA9PiB7XG4gIHRyeSB7XG4gICAgY29uc3QgcmVmcmVzaFRva2VuID0gcmVxLmNvb2tpZXM/LnJlZnJlc2hUb2tlbjtcblxuICAgIGlmICghcmVmcmVzaFRva2VuKSB7XG4gICAgICByZXMuc3RhdHVzKDQwMSkuanNvbih7XG4gICAgICAgIGVycm9yOiAnVW5hdXRob3JpemVkJyxcbiAgICAgICAgbWVzc2FnZTogJ1JlZnJlc2ggdG9rZW4gbsOjbyBlbmNvbnRyYWRvJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IEF1dGhTZXJ2aWNlLnJlZnJlc2hBY2Nlc3NUb2tlbihyZWZyZXNoVG9rZW4pO1xuXG4gICAgaWYgKHJlc3VsdC5zdWNjZXNzKSB7XG4gICAgICByZXMuY29va2llKCdhY2Nlc3NUb2tlbicsIHJlc3VsdC5hY2Nlc3NUb2tlbiwge1xuICAgICAgICBodHRwT25seTogdHJ1ZSxcbiAgICAgICAgc2VjdXJlOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nLFxuICAgICAgICBzYW1lU2l0ZTogJ3N0cmljdCcsXG4gICAgICAgIG1heEFnZTogMTUgKiA2MCAqIDEwMDAsXG4gICAgICAgIHBhdGg6ICcvYXBpJyxcbiAgICAgIH0pO1xuXG4gICAgICByZXMuanNvbih7XG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgIGRhdGE6IHtcbiAgICAgICAgICBhY2Nlc3NUb2tlbjogcmVzdWx0LmFjY2Vzc1Rva2VuLFxuICAgICAgICB9LFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgcmVzLnN0YXR1cyg0MDEpLmpzb24oe1xuICAgICAgZXJyb3I6ICdVbmF1dGhvcml6ZWQnLFxuICAgICAgbWVzc2FnZTogJ1JlZnJlc2ggdG9rZW4gaW52w6FsaWRvIG91IGV4cGlyYWRvJyxcbiAgICB9KTtcbiAgfSBjYXRjaCAoZXJyb3I6IGFueSkge1xuICAgIGNvbnNvbGUuZXJyb3IoJ1Rva2VuIHJlZnJlc2ggZXJyb3I6JywgZXJyb3IpO1xuXG4gICAgcmVzLnN0YXR1cyg0MDEpLmpzb24oe1xuICAgICAgZXJyb3I6ICdVbmF1dGhvcml6ZWQnLFxuICAgICAgbWVzc2FnZTogJ0ZhbGhhIGFvIHJlbm92YXIgdG9rZW4nLFxuICAgIH0pO1xuICB9XG59KTtcblxuLyoqXG4gKiBQT1NUIC9hcGkvYXV0aC9sb2dvdXRcbiAqIExvZ291dCAocmV2b2dhIHNlc3PDo28gYXR1YWwpXG4gKi9cbnJvdXRlci5wb3N0KCcvbG9nb3V0JywgYXN5bmMgKHJlcTogUmVxdWVzdCwgcmVzOiBSZXNwb25zZSkgPT4ge1xuICB0cnkge1xuICAgIGNvbnN0IHNlc3Npb24gPSBnZXRTZXNzaW9uRnJvbVJlcXVlc3QocmVxKTtcbiAgICBjb25zdCByZWZyZXNoVG9rZW4gPSByZXEuY29va2llcz8ucmVmcmVzaFRva2VuO1xuXG4gICAgaWYgKHNlc3Npb24/LnNlc3Npb25JZCB8fCByZWZyZXNoVG9rZW4pIHtcbiAgICAgIGF3YWl0IEF1dGhTZXJ2aWNlLmxvZ291dCh7XG4gICAgICAgIHNlc3Npb25JZDogc2Vzc2lvbj8uc2Vzc2lvbklkLFxuICAgICAgICByZWZyZXNoVG9rZW4sXG4gICAgICAgIGlwQWRkcmVzczogcmVxLmlwIHx8IHJlcS5zb2NrZXQucmVtb3RlQWRkcmVzcyB8fCAnJyxcbiAgICAgICAgdXNlckFnZW50OiByZXEuZ2V0KCd1c2VyLWFnZW50JykgfHwgJycsXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBMaW1wYXIgY29va2llc1xuICAgIHJlcy5jbGVhckNvb2tpZSgnYWNjZXNzVG9rZW4nLCB7XG4gICAgICBodHRwT25seTogdHJ1ZSxcbiAgICAgIHNlY3VyZTogcHJvY2Vzcy5lbnYuTk9ERV9FTlYgPT09ICdwcm9kdWN0aW9uJyxcbiAgICAgIHNhbWVTaXRlOiAnc3RyaWN0JyxcbiAgICAgIHBhdGg6ICcvYXBpJyxcbiAgICB9KTtcblxuICAgIHJlcy5jbGVhckNvb2tpZSgncmVmcmVzaFRva2VuJywge1xuICAgICAgaHR0cE9ubHk6IHRydWUsXG4gICAgICBzZWN1cmU6IHByb2Nlc3MuZW52Lk5PREVfRU5WID09PSAncHJvZHVjdGlvbicsXG4gICAgICBzYW1lU2l0ZTogJ3N0cmljdCcsXG4gICAgICBwYXRoOiAnL2FwaS9hdXRoL3JlZnJlc2gnLFxuICAgIH0pO1xuXG4gICAgcmVzLmpzb24oe1xuICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgIG1lc3NhZ2U6ICdMb2dvdXQgcmVhbGl6YWRvIGNvbSBzdWNlc3NvJyxcbiAgICB9KTtcbiAgfSBjYXRjaCAoZXJyb3I6IGFueSkge1xuICAgIGNvbnNvbGUuZXJyb3IoJ0xvZ291dCBlcnJvcjonLCBlcnJvcik7XG5cbiAgICAvLyBNZXNtbyBjb20gZXJybywgbGltcGFyIGNvb2tpZXNcbiAgICByZXMuY2xlYXJDb29raWUoJ2FjY2Vzc1Rva2VuJywge1xuICAgICAgaHR0cE9ubHk6IHRydWUsXG4gICAgICBzZWN1cmU6IHByb2Nlc3MuZW52Lk5PREVfRU5WID09PSAncHJvZHVjdGlvbicsXG4gICAgICBzYW1lU2l0ZTogJ3N0cmljdCcsXG4gICAgICBwYXRoOiAnL2FwaScsXG4gICAgfSk7XG5cbiAgICByZXMuY2xlYXJDb29raWUoJ3JlZnJlc2hUb2tlbicsIHtcbiAgICAgIGh0dHBPbmx5OiB0cnVlLFxuICAgICAgc2VjdXJlOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nLFxuICAgICAgc2FtZVNpdGU6ICdzdHJpY3QnLFxuICAgICAgcGF0aDogJy9hcGkvYXV0aC9yZWZyZXNoJyxcbiAgICB9KTtcblxuICAgIHJlcy5zdGF0dXMoNTAwKS5qc29uKHtcbiAgICAgIGVycm9yOiAnSW50ZXJuYWwgU2VydmVyIEVycm9yJyxcbiAgICAgIG1lc3NhZ2U6ICdFcnJvIGFvIGZhemVyIGxvZ291dCcsXG4gICAgfSk7XG4gIH1cbn0pO1xuXG4vKipcbiAqIFBPU1QgL2FwaS9hdXRoL2xvZ291dC1hbGxcbiAqIExvZ291dCBkZSB0b2RvcyBvcyBkaXNwb3NpdGl2b3MgKHJldm9nYSB0b2RhcyBhcyBzZXNzw7VlcylcbiAqL1xucm91dGVyLnBvc3QoJy9sb2dvdXQtYWxsJywgYXN5bmMgKHJlcTogUmVxdWVzdCwgcmVzOiBSZXNwb25zZSkgPT4ge1xuICB0cnkge1xuICAgIGNvbnN0IHNlc3Npb24gPSBnZXRTZXNzaW9uRnJvbVJlcXVlc3QocmVxKTtcblxuICAgIGlmICghc2Vzc2lvbj8udXNlcklkKSB7XG4gICAgICByZXMuc3RhdHVzKDQwMSkuanNvbih7XG4gICAgICAgIGVycm9yOiAnVW5hdXRob3JpemVkJyxcbiAgICAgICAgbWVzc2FnZTogJ1VzdcOhcmlvIG7Do28gYXV0ZW50aWNhZG8nLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgYXdhaXQgQXV0aFNlcnZpY2UubG9nb3V0QWxsKHtcbiAgICAgIHVzZXJJZDogc2Vzc2lvbi51c2VySWQsXG4gICAgICBpcEFkZHJlc3M6IHJlcS5pcCB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJycsXG4gICAgICB1c2VyQWdlbnQ6IHJlcS5nZXQoJ3VzZXItYWdlbnQnKSB8fCAnJyxcbiAgICB9KTtcblxuICAgIC8vIExpbXBhciBjb29raWVzXG4gICAgcmVzLmNsZWFyQ29va2llKCdhY2Nlc3NUb2tlbicsIHtcbiAgICAgIGh0dHBPbmx5OiB0cnVlLFxuICAgICAgc2VjdXJlOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nLFxuICAgICAgc2FtZVNpdGU6ICdzdHJpY3QnLFxuICAgICAgcGF0aDogJy9hcGknLFxuICAgIH0pO1xuXG4gICAgcmVzLmNsZWFyQ29va2llKCdyZWZyZXNoVG9rZW4nLCB7XG4gICAgICBodHRwT25seTogdHJ1ZSxcbiAgICAgIHNlY3VyZTogcHJvY2Vzcy5lbnYuTk9ERV9FTlYgPT09ICdwcm9kdWN0aW9uJyxcbiAgICAgIHNhbWVTaXRlOiAnc3RyaWN0JyxcbiAgICAgIHBhdGg6ICcvYXBpL2F1dGgvcmVmcmVzaCcsXG4gICAgfSk7XG5cbiAgICByZXMuanNvbih7XG4gICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgbWVzc2FnZTogJ1RvZG9zIG9zIGRpc3Bvc2l0aXZvcyBmb3JhbSBkZXNjb25lY3RhZG9zJyxcbiAgICB9KTtcbiAgfSBjYXRjaCAoZXJyb3I6IGFueSkge1xuICAgIGNvbnNvbGUuZXJyb3IoJ0xvZ291dCBhbGwgZXJyb3I6JywgZXJyb3IpO1xuXG4gICAgcmVzLmNsZWFyQ29va2llKCdhY2Nlc3NUb2tlbicsIHtcbiAgICAgIGh0dHBPbmx5OiB0cnVlLFxuICAgICAgc2VjdXJlOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nLFxuICAgICAgc2FtZVNpdGU6ICdzdHJpY3QnLFxuICAgICAgcGF0aDogJy9hcGknLFxuICAgIH0pO1xuXG4gICAgcmVzLmNsZWFyQ29va2llKCdyZWZyZXNoVG9rZW4nLCB7XG4gICAgICBodHRwT25seTogdHJ1ZSxcbiAgICAgIHNlY3VyZTogcHJvY2Vzcy5lbnYuTk9ERV9FTlYgPT09ICdwcm9kdWN0aW9uJyxcbiAgICAgIHNhbWVTaXRlOiAnc3RyaWN0JyxcbiAgICAgIHBhdGg6ICcvYXBpL2F1dGgvcmVmcmVzaCcsXG4gICAgfSk7XG5cbiAgICByZXMuc3RhdHVzKDUwMCkuanNvbih7XG4gICAgICBlcnJvcjogJ0ludGVybmFsIFNlcnZlciBFcnJvcicsXG4gICAgICBtZXNzYWdlOiAnRXJybyBhbyBkZXNjb25lY3RhciB0b2RvcyBvcyBkaXNwb3NpdGl2b3MnLFxuICAgIH0pO1xuICB9XG59KTtcblxuLyoqXG4gKiBHRVQgL2FwaS9hdXRoL21lXG4gKiBEYWRvcyBkbyB1c3XDoXJpbyBhdXRlbnRpY2FkbyBhdHVhbFxuICovXG5yb3V0ZXIuZ2V0KCcvbWUnLCBhc3luYyAocmVxOiBSZXF1ZXN0LCByZXM6IFJlc3BvbnNlKSA9PiB7XG4gIHRyeSB7XG4gICAgY29uc3Qgc2Vzc2lvbiA9IGdldFNlc3Npb25Gcm9tUmVxdWVzdChyZXEpO1xuXG4gICAgaWYgKCFzZXNzaW9uPy51c2VySWQpIHtcbiAgICAgIHJlcy5zdGF0dXMoNDAxKS5qc29uKHtcbiAgICAgICAgZXJyb3I6ICdVbmF1dGhvcml6ZWQnLFxuICAgICAgICBtZXNzYWdlOiAnVXN1w6FyaW8gbsOjbyBhdXRlbnRpY2FkbycsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCB1c2VyID0gYXdhaXQgQXV0aFNlcnZpY2UuZ2V0VXNlckJ5SWQoc2Vzc2lvbi51c2VySWQpO1xuXG4gICAgaWYgKCF1c2VyKSB7XG4gICAgICByZXMuc3RhdHVzKDQwNCkuanNvbih7XG4gICAgICAgIGVycm9yOiAnTm90IEZvdW5kJyxcbiAgICAgICAgbWVzc2FnZTogJ1VzdcOhcmlvIG7Do28gZW5jb250cmFkbycsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICByZXMuanNvbih7XG4gICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgZGF0YToge1xuICAgICAgICB1c2VyOiB7XG4gICAgICAgICAgaWQ6IHVzZXIuaWQsXG4gICAgICAgICAgZW1haWw6IHVzZXIuZW1haWwsXG4gICAgICAgICAgbmFtZTogdXNlci5uYW1lLFxuICAgICAgICAgIG1mYUVuYWJsZWQ6IHVzZXIubWZhRW5hYmxlZCxcbiAgICAgICAgICB3ZWJhdXRobkVuYWJsZWQ6IHVzZXIud2ViYXV0aG5FbmFibGVkLFxuICAgICAgICAgIGNyZWF0ZWRBdDogdXNlci5jcmVhdGVkQXQsXG4gICAgICAgIH0sXG4gICAgICAgIHNlc3Npb246IHtcbiAgICAgICAgICBzZXNzaW9uSWQ6IHNlc3Npb24uc2Vzc2lvbklkLFxuICAgICAgICAgIGRldmljZUlkOiBzZXNzaW9uLmRldmljZUlkLFxuICAgICAgICAgIGNyZWF0ZWRBdDogc2Vzc2lvbi5jcmVhdGVkQXQsXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0pO1xuICB9IGNhdGNoIChlcnJvcjogYW55KSB7XG4gICAgY29uc29sZS5lcnJvcignR2V0IHVzZXIgZXJyb3I6JywgZXJyb3IpO1xuXG4gICAgcmVzLnN0YXR1cyg1MDApLmpzb24oe1xuICAgICAgZXJyb3I6ICdJbnRlcm5hbCBTZXJ2ZXIgRXJyb3InLFxuICAgICAgbWVzc2FnZTogJ0Vycm8gYW8gYnVzY2FyIGRhZG9zIGRvIHVzdcOhcmlvJyxcbiAgICB9KTtcbiAgfVxufSk7XG5cbmV4cG9ydCB7IHJvdXRlciBhcyBhdXRoUm91dGVzIH07XG4iXX0=
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
declare const router: import("express-serve-static-core").Router;
export { router as authRoutes };
//# sourceMappingURL=auth.d.ts.map
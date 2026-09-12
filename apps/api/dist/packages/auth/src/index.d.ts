/**
 * @zero/auth - Módulo de Autenticação e Gerenciamento de Sessão
 *
 * RESPONSABILIDADES:
 * - Registro de usuários com validação segura
 * - Login com verificação de senha (Argon2id)
 * - MFA TOTP obrigatório
 * - WebAuthn/Passkeys opcional
 * - Gerenciamento de sessões (JWT + refresh tokens)
 * - Rate limiting para tentativas de login
 * - Auditoria de eventos de autenticação
 *
 * PRINCÍPIOS DE SEGURANÇA:
 * - NUNCA armazenar senhas em texto puro
 * - NUNCA logar dados sensíveis
 * - SEMPRE validar no backend
 * - SEMPRE usar timing-safe comparison
 * - MFA obrigatório após registro
 * - Sessions com expiry curto (15min access, 7d refresh)
 */
export type { AuthRequest, AuthResponse, RegisterInput, LoginInput, MFAVerificationInput, SessionData, JWTPayload, RefreshTokenPayload, AuthAuditEvent, } from './types';
export { AuthService } from './services/auth.service';
export { SessionService } from './services/session.service';
export { MFAService } from './services/mfa.service';
export { WebAuthService } from './services/webauthn.service';
export { generateAuthTokens, verifyJWT, decodeJWT } from './utils/tokens';
export { validatePassword, validateEmail } from './utils/validation';
export { AUTH_CONSTANTS } from './constants';
//# sourceMappingURL=index.d.ts.map
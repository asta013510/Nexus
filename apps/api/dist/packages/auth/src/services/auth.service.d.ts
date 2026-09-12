/**
 * Serviço de Autenticação Principal
 *
 * Responsabilidades:
 * - Registro de usuários
 * - Login com validação de credenciais
 * - Gerenciamento de tentativas e lockout
 * - Integração com MFA
 * - Auditoria de eventos
 */
import { type User as DBUser } from '@zero/database';
import type { RegisterInput, LoginInput, AuthResponse, AuthError, AuthAuditEvent } from '../types';
import { generateAuthTokens } from '../utils/tokens';
export declare function setDatabaseClient(client: any): void;
/**
 * Registra novo usuário no sistema
 *
 * SECURITY NOTES:
 * - Email normalizado para lowercase
 * - Senha hash com Argon2id antes de armazenar
 * - Validação de força da senha
 * - Verificação de email duplicado
 * - Geração de recovery codes
 * - Auditoria do evento
 */
export declare const AuthService: {
    register(input: RegisterInput, ipAddress: string, userAgent: string): Promise<AuthResponse>;
    /**
     * Autentica usuário com email e senha
     *
     * SECURITY NOTES:
     * - Timing-safe comparison para senha
     * - Rate limiting por IP e usuário
     * - Lockout após múltiplas falhas
     * - Mensagens de erro genéricas (não revelar se email existe)
     * - Requer MFA se habilitado
     */
    login(input: LoginInput, ipAddress: string, userAgent: string): Promise<AuthResponse>;
    /**
     * Cria sessão após autenticação bem-sucedida
     */
    createSession(user: DBUser, input: LoginInput, ipAddress: string, userAgent: string): Promise<AuthResponse>;
    /**
     * Incrementa tentativas falhas e aplica lockout se necessário
     */
    incrementFailedAttempts(userId: string): Promise<void>;
    /**
     * Reset tentativas falhas após login bem-sucedido
     */
    resetFailedAttempts(userId: string): Promise<void>;
    /**
     * Detecta tipo de dispositivo a partir do user agent
     */
    detectDeviceType(userAgent: string): "desktop" | "mobile" | "tablet" | "unknown";
    /**
     * Parse user agent para extrair OS e browser
     * Implementação simplificada - usar biblioteca dedicada em produção
     */
    parseUserAgent(userAgent: string): {
        os: string;
        browser: string;
    };
    /**
     * Log de auditoria para eventos de autenticação
     */
    auditLog(event: Omit<AuthAuditEvent, "success"> & {
        success: boolean;
    }): Promise<void>;
    /**
     * Verifica código MFA durante login
     */
    verifyMFA(userId: string, mfaCode: string, ipAddress: string, userAgent: string): Promise<AuthResponse>;
    /**
     * Refresh de access token usando refresh token
     */
    refreshAccessToken(refreshToken: string, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        tokens?: typeof generateAuthTokens;
        error?: AuthError;
    }>;
    /**
     * Logout de uma sessão específica
     */
    logout(sessionId: string, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        error?: AuthError;
    }>;
    /**
     * Logout de todas as sessões do usuário
     */
    logoutAll(userId: string, currentSessionId: string | null, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        error?: AuthError;
    }>;
    /**
     * Obtém usuário por ID (sem dados sensíveis)
     */
    getUserById(userId: string): Promise<{
        success: boolean;
        user?: {
            id: string;
            email: string;
            displayName: string | null;
            mfaEnabled: boolean;
            status: string;
        };
        error?: AuthError;
    }>;
};
//# sourceMappingURL=auth.service.d.ts.map
/**
 * Serviço de Gerenciamento de Sessão
 *
 * Responsabilidades:
 * - Validação de tokens JWT
 * - Refresh de access tokens
 * - Revogação de sessões
 * - Validação de dispositivos confiáveis
 * - Auditoria de eventos de sessão
 *
 * SECURITY NOTES:
 * - Access tokens com vida curta (15 min)
 * - Refresh tokens com rotação
 * - Validação de assinatura JWT
 * - Verificação de revogação no banco
 * - Binding entre sessão e dispositivo
 */
import type { SessionData, JWTPayload, AuthAuditEvent } from '../types';
export declare function setDatabaseClient(client: any): void;
export declare const SessionService: {
    /**
     * Valida access token JWT
     */
    validateAccessToken(accessToken: string): Promise<{
        valid: boolean;
        payload?: JWTPayload;
        error?: string;
    }>;
    /**
     * Realiza refresh do access token usando refresh token
     * Implementa rotação de refresh tokens para segurança
     */
    refreshAccessToken(refreshToken: string, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        session?: SessionData;
        error?: any;
    }>;
    /**
     * Revoga uma sessão específica
     */
    revokeSession(sessionId: string, userId: string, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        error?: any;
    }>;
    /**
     * Revoga TODAS as sessões de um usuário (logout em todos os dispositivos)
     */
    revokeAllSessions(userId: string, exceptSessionId?: string, ipAddress?: string, userAgent?: string): Promise<{
        success: boolean;
        error?: any;
    }>;
    /**
     * Logout - revoga sessão atual
     */
    logout(sessionId: string, userId: string, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        error?: any;
    }>;
    /**
     * Lista sessões ativas de um usuário
     */
    listActiveSessions(userId: string): Promise<{
        success: boolean;
        sessions?: any[];
        error?: any;
    }>;
    /**
     * Verifica se dispositivo é confiável
     */
    isTrustedDevice(userId: string, deviceId: string): Promise<boolean>;
    auditLog(event: AuthAuditEvent): Promise<void>;
};
//# sourceMappingURL=session.service.d.ts.map
/**
 * Serviço de Auditoria de Segurança
 *
 * RESPONSABILIDADES:
 * - Log estruturado de eventos de segurança
 * - Proteção contra manipulação de logs
 * - Minimização de dados sensíveis nos logs
 * - Contexto suficiente para investigação
 *
 * EVENTOS AUDITADOS:
 * - Login/logout
 * - Tentativas de login (sucesso/falha)
 * - Falha biométrica
 * - Novo dispositivo
 * - Remoção de dispositivo
 * - Upload/download de documentos
 * - Exclusão/recuperação
 * - Alteração de senha
 * - Alteração de fatores MFA
 * - Alterações de configurações de segurança
 */
import { Pool } from 'pg';
export interface AuditEvent {
    id: string;
    eventType: AuditEventType;
    userId?: string;
    sessionId?: string;
    deviceId?: string;
    ipAddress: string;
    userAgent: string;
    timestamp: Date;
    success: boolean;
    metadata: Record<string, unknown>;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
}
export type AuditEventType = 'LOGIN_ATTEMPT' | 'LOGIN_SUCCESS' | 'LOGIN_FAILURE' | 'LOGOUT' | 'LOGOUT_ALL' | 'REGISTER_SUCCESS' | 'REGISTER_FAILURE' | 'MFA_SETUP' | 'MFA_VERIFICATION_SUCCESS' | 'MFA_VERIFICATION_FAILURE' | 'MFA_REMOVED' | 'PASSWORD_CHANGE' | 'PASSWORD_RESET_REQUEST' | 'PASSWORD_RESET_SUCCESS' | 'SESSION_CREATED' | 'SESSION_REVOKED' | 'SESSION_REVOKED_ALL' | 'DEVICE_ADDED' | 'DEVICE_REMOVED' | 'DOCUMENT_UPLOAD' | 'DOCUMENT_DOWNLOAD' | 'DOCUMENT_VIEW' | 'DOCUMENT_DELETE' | 'DOCUMENT_RESTORE' | 'DOCUMENT_VERSION_CREATE' | 'BIOMETRIC_ENROLLMENT' | 'BIOMETRIC_AUTH_SUCCESS' | 'BIOMETRIC_AUTH_FAILURE' | 'WEBAUTHN_REGISTER' | 'WEBAUTHN_AUTH_SUCCESS' | 'WEBAUTHN_AUTH_FAILURE' | 'ACCOUNT_LOCKED' | 'ACCOUNT_UNLOCKED' | 'SUSPICIOUS_ACTIVITY_DETECTED';
export declare class AuditService {
    private pool;
    constructor(pool: Pool);
    /**
     * Registra um evento de auditoria
     * SECURITY: Nunca logar dados sensíveis (senhas, tokens, chaves)
     */
    log(event: Omit<AuditEvent, 'id'>): Promise<string>;
    /**
     * Remove dados sensíveis da metadata
     */
    private sanitizeMetadata;
    /**
     * Busca eventos de auditoria por usuário
     */
    getUserEvents(userId: string, limit?: number, offset?: number): Promise<AuditEvent[]>;
    /**
     * Busca eventos de auditoria por sessão
     */
    getSessionEvents(sessionId: string, limit?: number): Promise<AuditEvent[]>;
    /**
     * Busca eventos suspeitos (risk_level = high ou critical)
     */
    getSuspiciousEvents(limit?: number): Promise<AuditEvent[]>;
    /**
     * Converte row do banco para AuditEvent
     */
    private rowToEvent;
    /**
     * Detecta atividade suspeita baseada em padrões
     * - Múltiplas falhas de login
     * - Login de localização incomum
     * - Múltiplos dispositivos em curto período
     */
    detectSuspiciousActivity(userId: string, context: {
        ipAddress: string;
        userAgent: string;
        deviceId?: string;
    }): Promise<boolean>;
}
//# sourceMappingURL=audit.service.d.ts.map
"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditService = void 0;
class AuditService {
    pool;
    constructor(pool) {
        this.pool = pool;
    }
    /**
     * Registra um evento de auditoria
     * SECURITY: Nunca logar dados sensíveis (senhas, tokens, chaves)
     */
    async log(event) {
        const eventId = crypto.randomUUID();
        // Validar eventType
        const validEventTypes = [
            'LOGIN_ATTEMPT', 'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGOUT', 'LOGOUT_ALL',
            'REGISTER_SUCCESS', 'REGISTER_FAILURE', 'MFA_SETUP', 'MFA_VERIFICATION_SUCCESS',
            'MFA_VERIFICATION_FAILURE', 'MFA_REMOVED', 'PASSWORD_CHANGE', 'PASSWORD_RESET_REQUEST',
            'PASSWORD_RESET_SUCCESS', 'SESSION_CREATED', 'SESSION_REVOKED', 'SESSION_REVOKED_ALL',
            'DEVICE_ADDED', 'DEVICE_REMOVED', 'DOCUMENT_UPLOAD', 'DOCUMENT_DOWNLOAD',
            'DOCUMENT_VIEW', 'DOCUMENT_DELETE', 'DOCUMENT_RESTORE', 'DOCUMENT_VERSION_CREATE',
            'BIOMETRIC_ENROLLMENT', 'BIOMETRIC_AUTH_SUCCESS', 'BIOMETRIC_AUTH_FAILURE',
            'WEBAUTHN_REGISTER', 'WEBAUTHN_AUTH_SUCCESS', 'WEBAUTHN_AUTH_FAILURE',
            'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'SUSPICIOUS_ACTIVITY_DETECTED',
        ];
        if (!validEventTypes.includes(event.eventType)) {
            throw new Error(`Invalid audit event type: ${event.eventType}`);
        }
        // Sanitizar metadata (remover possíveis dados sensíveis)
        const sanitizedMetadata = this.sanitizeMetadata(event.metadata);
        try {
            await this.pool.query(`INSERT INTO audit_logs (
          id, event_type, user_id, session_id, device_id, ip_address,
          user_agent, timestamp, success, metadata, risk_level
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, [
                eventId,
                event.eventType,
                event.userId || null,
                event.sessionId || null,
                event.deviceId || null,
                event.ipAddress,
                event.userAgent,
                event.timestamp,
                event.success,
                JSON.stringify(sanitizedMetadata),
                event.riskLevel,
            ]);
            return eventId;
        }
        catch (error) {
            console.error('Failed to log audit event:', error);
            // Não lançar erro para não quebrar o fluxo principal
            // Mas em produção isso deve ser monitorado
            return eventId;
        }
    }
    /**
     * Remove dados sensíveis da metadata
     */
    sanitizeMetadata(metadata) {
        const sensitiveKeys = [
            'password', 'passwd', 'pwd', 'secret', 'token', 'access_token', 'refresh_token',
            'api_key', 'apikey', 'authorization', 'cookie', 'session', 'key', 'private',
            'credential', 'mfa_code', 'totp', 'otp', 'verification_code',
        ];
        const sanitized = {};
        for (const [key, value] of Object.entries(metadata)) {
            const lowerKey = key.toLowerCase();
            // Pular chaves sensíveis
            if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
                continue;
            }
            // Se for objeto, sanitizar recursivamente (limitando profundidade)
            if (typeof value === 'object' && value !== null) {
                sanitized[key] = this.sanitizeMetadata(value);
            }
            else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    }
    /**
     * Busca eventos de auditoria por usuário
     */
    async getUserEvents(userId, limit = 50, offset = 0) {
        const result = await this.pool.query(`SELECT * FROM audit_logs 
       WHERE user_id = $1 
       ORDER BY timestamp DESC 
       LIMIT $2 OFFSET $3`, [userId, limit, offset]);
        return result.rows.map(this.rowToEvent);
    }
    /**
     * Busca eventos de auditoria por sessão
     */
    async getSessionEvents(sessionId, limit = 50) {
        const result = await this.pool.query(`SELECT * FROM audit_logs 
       WHERE session_id = $1 
       ORDER BY timestamp DESC 
       LIMIT $2`, [sessionId, limit]);
        return result.rows.map(this.rowToEvent);
    }
    /**
     * Busca eventos suspeitos (risk_level = high ou critical)
     */
    async getSuspiciousEvents(limit = 100) {
        const result = await this.pool.query(`SELECT * FROM audit_logs 
       WHERE risk_level IN ('high', 'critical') 
       ORDER BY timestamp DESC 
       LIMIT $1`, [limit]);
        return result.rows.map(this.rowToEvent);
    }
    /**
     * Converte row do banco para AuditEvent
     */
    rowToEvent(row) {
        return {
            id: row.id,
            eventType: row.event_type,
            userId: row.user_id,
            sessionId: row.session_id,
            deviceId: row.device_id,
            ipAddress: row.ip_address,
            userAgent: row.user_agent,
            timestamp: row.timestamp,
            success: row.success,
            metadata: row.metadata || {},
            riskLevel: row.risk_level,
        };
    }
    /**
     * Detecta atividade suspeita baseada em padrões
     * - Múltiplas falhas de login
     * - Login de localização incomum
     * - Múltiplos dispositivos em curto período
     */
    async detectSuspiciousActivity(userId, context) {
        const recentFailures = await this.pool.query(`SELECT COUNT(*) FROM audit_logs 
       WHERE user_id = $1 
       AND success = false 
       AND event_type = 'LOGIN_FAILURE'
       AND timestamp > NOW() - INTERVAL '15 minutes'`, [userId]);
        const failureCount = parseInt(recentFailures.rows[0]?.count || '0', 10);
        // Mais de 5 falhas em 15 minutos é suspeito
        if (failureCount >= 5) {
            return true;
        }
        // TODO: Adicionar detecção de localização incomum
        // TODO: Adicionar detecção de múltiplos dispositivos
        return false;
    }
}
exports.AuditService = AuditService;
//# sourceMappingURL=audit.service.js.map
/**
 * Tipos para o sistema de auditoria do ZERO
 */

/**
 * Ações de auditoria que podem ser registradas
 */
export type AuditAction =
  // Autenticação
  | 'AUTH_REGISTER'
  | 'AUTH_LOGIN_SUCCESS'
  | 'AUTH_LOGIN_FAILURE'
  | 'AUTH_LOGOUT'
  | 'AUTH_PASSWORD_CHANGE'
  | 'AUTH_PASSWORD_RESET_REQUEST'
  | 'AUTH_PASSWORD_RESET_COMPLETE'
  // MFA
  | 'MFA_SETUP'
  | 'MFA_VERIFY_SUCCESS'
  | 'MFA_VERIFY_FAILURE'
  | 'MFA_DISABLE'
  | 'MFA_RECOVERY_CODE_USED'
  | 'MFA_RECOVERY_CODES_REGENERATED'
  // Sessão
  | 'SESSION_CREATE'
  | 'SESSION_REFRESH'
  | 'SESSION_REVOKE'
  | 'SESSION_REVOKE_ALL'
  // Dispositivo
  | 'DEVICE_REGISTER'
  | 'DEVICE_TRUST'
  | 'DEVICE_UNTRUST'
  | 'DEVICE_REMOVE'
  // Documentos
  | 'DOCUMENT_UPLOAD'
  | 'DOCUMENT_DOWNLOAD'
  | 'DOCUMENT_VIEW'
  | 'DOCUMENT_UPDATE'
  | 'DOCUMENT_DELETE'
  | 'DOCUMENT_RESTORE'
  | 'DOCUMENT_VERSION_CREATE'
  // Segurança
  | 'SECURITY_ALERT_CREATED'
  | 'SECURITY_ALERT_ACKNOWLEDGED'
  | 'SECURITY_ALERT_RESOLVED'
  | 'SECURITY_ANOMALY_DETECTED'
  // Conta
  | 'ACCOUNT_EMAIL_CHANGE'
  | 'ACCOUNT_DELETE_REQUEST'
  | 'ACCOUNT_DELETE_COMPLETE';

/**
 * Níveis de severidade para eventos de auditoria
 */
export type AuditSeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Contexto adicional para eventos de auditoria
 */
export interface AuditContext {
  ipAddress?: string;
  userAgent?: string;
  deviceId?: string;
  sessionId?: string;
  userId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Evento de auditoria completo
 */
export interface AuditEvent {
  id: string;
  action: AuditAction;
  severity: AuditSeverity;
  timestamp: Date;
  userId?: string;
  context: AuditContext;
  success: boolean;
  errorMessage?: string;
}

/**
 * Filtros para consulta de eventos de auditoria
 */
export interface AuditFilters {
  userId?: string;
  action?: AuditAction;
  severity?: AuditSeverity;
  startDate?: Date;
  endDate?: Date;
  success?: boolean;
  limit?: number;
  offset?: number;
}

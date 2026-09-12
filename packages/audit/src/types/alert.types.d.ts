/**
 * Tipos para sistema de alertas de segurança do ZERO
 */
/**
 * Tipo de alerta de segurança
 */
export type AlertType = 'security' | 'anomalous_activity' | 'account_change' | 'device' | 'session' | 'document';
/**
 * Prioridade do alerta
 */
export type AlertPriority = 'critical' | 'high' | 'medium' | 'low';
/**
 * Status do alerta
 */
export type AlertStatus = 'pending' | 'acknowledged' | 'resolved' | 'false_positive';
/**
 * Dados detalhados de um alerta
 */
export interface Alert {
    id: string;
    userId: string;
    type: AlertType;
    priority: AlertPriority;
    status: AlertStatus;
    title: string;
    description: string;
    createdAt: Date;
    updatedAt: Date;
    acknowledgedAt?: Date;
    acknowledgedBy?: string;
    resolvedAt?: Date;
    resolvedBy?: string;
    resolutionNotes?: string;
    context: {
        ipAddress?: string;
        userAgent?: string;
        deviceId?: string;
        sessionId?: string;
        location?: {
            country?: string;
            region?: string;
            city?: string;
        };
        metadata?: Record<string, unknown>;
    };
    relatedAlertIds?: string[];
}
/**
 * Dados para criação de novo alerta
 */
export interface CreateAlertData {
    userId: string;
    type: AlertType;
    priority: AlertPriority;
    title: string;
    description: string;
    context?: {
        ipAddress?: string;
        userAgent?: string;
        deviceId?: string;
        sessionId?: string;
        location?: Alert['context']['location'];
        metadata?: Record<string, unknown>;
    };
}
/**
 * Dados para atualização de alerta
 */
export interface UpdateAlertData {
    status?: AlertStatus;
    resolutionNotes?: string;
    metadata?: Record<string, unknown>;
}
/**
 * Filtros para busca de alertas
 */
export interface AlertFilters {
    userId?: string;
    type?: AlertType;
    priority?: AlertPriority;
    status?: AlertStatus;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
    offset?: number;
}
/**
 * Estatísticas de alertas
 */
export interface AlertStats {
    total: number;
    byPriority: Record<AlertPriority, number>;
    byStatus: Record<AlertStatus, number>;
    byType: Record<AlertType, number>;
    unreadCount: number;
    criticalUnresolved: number;
}
/**
 * Configurações de notificação de alertas por usuário
 */
export interface AlertNotificationSettings {
    email: boolean;
    push: boolean;
    sms: boolean;
    minPriority: AlertPriority;
    quietHours?: {
        enabled: boolean;
        startHour: number;
        endHour: number;
    };
}
//# sourceMappingURL=alert.types.d.ts.map
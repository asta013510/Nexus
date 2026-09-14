import type { AlertType, AlertPriority, AlertStatus } from '../types/alerts.js';
export interface CreateAlertInput {
    userId: string;
    type: AlertType;
    priority: AlertPriority;
    title: string;
    message: string;
    deviceId?: string;
    metadata?: Record<string, unknown>;
}
export interface AlertResponse {
    id: string;
    userId: string;
    type: AlertType;
    priority: AlertPriority;
    status: AlertStatus;
    title: string;
    message: string;
    deviceId: string | null;
    metadata: Record<string, unknown> | null;
    createdAt: Date;
    acknowledgedAt: Date | null;
    resolvedAt: Date | null;
}
export declare class AlertsService {
    private auditService;
    constructor();
    /**
     * Cria um novo alerta de segurança
     */
    createAlert(input: CreateAlertInput): Promise<AlertResponse>;
    /**
     * Cria alerta automático baseado em evento de segurança
     */
    createSecurityAlert(userId: string, eventType: string, deviceId?: string, metadata?: Record<string, unknown>): Promise<AlertResponse>;
    /**
     * Lista alertas do usuário
     */
    getUserAlerts(userId: string, options?: {
        limit?: number;
        offset?: number;
        status?: AlertStatus;
        priority?: AlertPriority;
        unacknowledgedOnly?: boolean;
    }): Promise<AlertResponse[]>;
    /**
     * Reconhece um alerta (usuário viu o alerta)
     */
    acknowledgeAlert(alertId: string, userId: string): Promise<AlertResponse>;
    /**
     * Resolve um alerta (problema foi tratado)
     */
    resolveAlert(alertId: string, userId: string): Promise<AlertResponse>;
    /**
     * Conta alertas não lidos por prioridade
     */
    getUnreadAlertsCount(userId: string): Promise<{
        critical: number;
        high: number;
        medium: number;
        low: number;
    }>;
    /**
     * Detecta comportamento anômalo e cria alertas automáticos
     */
    detectAnomalousBehavior(userId: string, context: {
        deviceId?: string;
        ipAddress?: string;
        userAgent?: string;
        location?: string;
        eventType: string;
        metadata?: Record<string, unknown>;
    }): Promise<AlertResponse | null>;
    /**
     * Verifica padrões de anomalia
     */
    private checkForAnomalies;
    /**
     * Configuração de alertas por tipo de evento
     */
    private getAlertConfigForEvent;
    /**
     * Mapeia entidade do banco para resposta da API
     */
    private mapToResponse;
}
//# sourceMappingURL=alerts.service.d.ts.map
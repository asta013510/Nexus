import type { AuditAction, AuditSeverity, AuditEvent, AuditFilters, AuditContext } from '../types';
/**
 * Serviço de Auditoria do ZERO
 *
 * Responsável por registrar e consultar eventos de auditoria
 * de forma imutável e segura.
 */
export declare class AuditService {
    /**
     * Registra um novo evento de auditoria
     */
    logEvent(action: AuditAction, userId: string, success: boolean, context?: AuditContext, severity?: AuditSeverity, errorMessage?: string): Promise<AuditEvent>;
    /**
     * Busca eventos de auditoria com filtros
     */
    getEvents(filters: AuditFilters): Promise<AuditEvent[]>;
    /**
     * Busca um evento específico por ID
     */
    getEventById(eventId: string): Promise<AuditEvent | null>;
    /**
     * Conta eventos de auditoria com filtros
     */
    countEvents(filters: AuditFilters): Promise<number>;
    /**
     * Exporta eventos de auditoria para análise externa
     * (Para backup, compliance, ou investigação forense)
     */
    exportEvents(userId: string, startDate: Date, endDate: Date, format?: 'json' | 'csv'): Promise<string>;
    /**
     * Limpa eventos antigos (para retenção de dados)
     * CUIDADO: Esta operação deve ser usada com extrema cautela
     * e apenas em conformidade com políticas de retenção aprovadas.
     */
    cleanupOldEvents(olderThan: Date, userId?: string): Promise<number>;
}
//# sourceMappingURL=audit.service.d.ts.map
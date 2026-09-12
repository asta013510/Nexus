"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditService = void 0;
const database_1 = require("@zero/database");
const schema_1 = require("@zero/database/schema");
const drizzle_orm_1 = require("drizzle-orm");
const shared_1 = require("@zero/shared");
/**
 * Serviço de Auditoria do ZERO
 *
 * Responsável por registrar e consultar eventos de auditoria
 * de forma imutável e segura.
 */
class AuditService {
    /**
     * Registra um novo evento de auditoria
     */
    async logEvent(action, userId, success, context = {}, severity = 'medium', errorMessage) {
        const eventId = (0, shared_1.generateUUID)();
        const timestamp = new Date();
        try {
            await database_1.db.insert(schema_1.auditLogs).values({
                id: eventId,
                userId,
                action,
                severity,
                timestamp,
                success,
                errorMessage: errorMessage || null,
                ipAddress: context.ipAddress || null,
                userAgent: context.userAgent || null,
                deviceId: context.deviceId || null,
                sessionId: context.sessionId || null,
                metadata: context.metadata ? JSON.stringify(context.metadata) : null,
            });
            return {
                id: eventId,
                action,
                severity,
                timestamp,
                userId,
                context,
                success,
                errorMessage,
            };
        }
        catch (error) {
            // Em caso de falha no logging, ainda retornamos o evento
            // mas logamos o erro em console (em produção, enviar para sistema de monitoramento)
            console.error('[AuditService] Failed to log event:', error);
            return {
                id: eventId,
                action,
                severity,
                timestamp,
                userId,
                context,
                success,
                errorMessage: errorMessage || error.message,
            };
        }
    }
    /**
     * Busca eventos de auditoria com filtros
     */
    async getEvents(filters) {
        const conditions = [];
        if (filters.userId) {
            conditions.push((0, drizzle_orm_1.eq)(schema_1.auditLogs.userId, filters.userId));
        }
        if (filters.action) {
            conditions.push((0, drizzle_orm_1.eq)(schema_1.auditLogs.action, filters.action));
        }
        if (filters.severity) {
            conditions.push((0, drizzle_orm_1.eq)(schema_1.auditLogs.severity, filters.severity));
        }
        if (filters.success !== undefined) {
            conditions.push((0, drizzle_orm_1.eq)(schema_1.auditLogs.success, filters.success));
        }
        if (filters.startDate) {
            conditions.push((0, drizzle_orm_1.gte)(schema_1.auditLogs.timestamp, filters.startDate));
        }
        if (filters.endDate) {
            conditions.push((0, drizzle_orm_1.lte)(schema_1.auditLogs.timestamp, filters.endDate));
        }
        const limit = filters.limit || 100;
        const offset = filters.offset || 0;
        const results = await database_1.db
            .select()
            .from(schema_1.auditLogs)
            .where(conditions.length > 0 ? (0, drizzle_orm_1.and)(...conditions) : undefined)
            .orderBy((0, drizzle_orm_1.desc)(schema_1.auditLogs.timestamp))
            .limit(limit)
            .offset(offset);
        return results.map((log) => ({
            id: log.id,
            action: log.action,
            severity: log.severity,
            timestamp: log.timestamp,
            userId: log.userId || undefined,
            context: {
                ipAddress: log.ipAddress || undefined,
                userAgent: log.userAgent || undefined,
                deviceId: log.deviceId || undefined,
                sessionId: log.sessionId || undefined,
                metadata: log.metadata ? JSON.parse(log.metadata) : undefined,
            },
            success: log.success,
            errorMessage: log.errorMessage || undefined,
        }));
    }
    /**
     * Busca um evento específico por ID
     */
    async getEventById(eventId) {
        const results = await database_1.db
            .select()
            .from(schema_1.auditLogs)
            .where((0, drizzle_orm_1.eq)(schema_1.auditLogs.id, eventId))
            .limit(1);
        if (results.length === 0) {
            return null;
        }
        const log = results[0];
        return {
            id: log.id,
            action: log.action,
            severity: log.severity,
            timestamp: log.timestamp,
            userId: log.userId || undefined,
            context: {
                ipAddress: log.ipAddress || undefined,
                userAgent: log.userAgent || undefined,
                deviceId: log.deviceId || undefined,
                sessionId: log.sessionId || undefined,
                metadata: log.metadata ? JSON.parse(log.metadata) : undefined,
            },
            success: log.success,
            errorMessage: log.errorMessage || undefined,
        };
    }
    /**
     * Conta eventos de auditoria com filtros
     */
    async countEvents(filters) {
        const conditions = [];
        if (filters.userId) {
            conditions.push((0, drizzle_orm_1.eq)(schema_1.auditLogs.userId, filters.userId));
        }
        if (filters.action) {
            conditions.push((0, drizzle_orm_1.eq)(schema_1.auditLogs.action, filters.action));
        }
        if (filters.severity) {
            conditions.push((0, drizzle_orm_1.eq)(schema_1.auditLogs.severity, filters.severity));
        }
        if (filters.success !== undefined) {
            conditions.push((0, drizzle_orm_1.eq)(schema_1.auditLogs.success, filters.success));
        }
        if (filters.startDate) {
            conditions.push((0, drizzle_orm_1.gte)(schema_1.auditLogs.timestamp, filters.startDate));
        }
        if (filters.endDate) {
            conditions.push((0, drizzle_orm_1.lte)(schema_1.auditLogs.timestamp, filters.endDate));
        }
        const result = await database_1.db
            .select({ count: (0, drizzle_orm_1.sql) `count(*)` })
            .from(schema_1.auditLogs)
            .where(conditions.length > 0 ? (0, drizzle_orm_1.and)(...conditions) : undefined);
        return Number(result[0]?.count || 0);
    }
    /**
     * Exporta eventos de auditoria para análise externa
     * (Para backup, compliance, ou investigação forense)
     */
    async exportEvents(userId, startDate, endDate, format = 'json') {
        const events = await this.getEvents({
            userId,
            startDate,
            endDate,
            limit: 10000, // Limite máximo para exportação
        });
        if (format === 'json') {
            return JSON.stringify(events, null, 2);
        }
        // CSV export (simplificado)
        const headers = ['id', 'action', 'severity', 'timestamp', 'userId', 'success', 'errorMessage'];
        const rows = events.map((e) => [
            e.id,
            e.action,
            e.severity,
            e.timestamp.toISOString(),
            e.userId || '',
            e.success,
            e.errorMessage || '',
        ].join(','));
        return [headers.join(','), ...rows].join('\n');
    }
    /**
     * Limpa eventos antigos (para retenção de dados)
     * CUIDADO: Esta operação deve ser usada com extrema cautela
     * e apenas em conformidade com políticas de retenção aprovadas.
     */
    async cleanupOldEvents(olderThan, userId) {
        const conditions = [(0, drizzle_orm_1.sql) `${schema_1.auditLogs.timestamp} < ${olderThan}`];
        if (userId) {
            conditions.push((0, drizzle_orm_1.eq)(schema_1.auditLogs.userId, userId));
        }
        // Nota: Em produção, esta operação deve ser:
        // 1. Logada em sistema separado
        // 2. Requerer aprovação de múltiplos administradores
        // 3. Executada em batch para não travar o banco
        const result = await database_1.db
            .delete(schema_1.auditLogs)
            .where((0, drizzle_orm_1.and)(...conditions));
        // Retorna número aproximado de linhas afetadas
        return 0; // Drizzle não retorna count diretamente
    }
}
exports.AuditService = AuditService;
//# sourceMappingURL=audit.service.js.map
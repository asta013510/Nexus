import { db } from '@zero/database';
import { auditLogs, users, devices, sessions } from '@zero/database/schema';
import { eq, and, gte, lte, desc, sql } from 'drizzle-orm';
import type { AuditAction, AuditSeverity, AuditEvent, AuditFilters, AuditContext } from '../types';
import { generateUUID } from '@zero/shared';

/**
 * Serviço de Auditoria do ZERO
 * 
 * Responsável por registrar e consultar eventos de auditoria
 * de forma imutável e segura.
 */
export class AuditService {
  /**
   * Registra um novo evento de auditoria
   */
  async logEvent(
    action: AuditAction,
    userId: string,
    success: boolean,
    context: AuditContext = {},
    severity: AuditSeverity = 'medium',
    errorMessage?: string
  ): Promise<AuditEvent> {
    const eventId = generateUUID();
    const timestamp = new Date();

    try {
      await db.insert(auditLogs).values({
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
    } catch (error) {
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
        errorMessage: errorMessage || (error as Error).message,
      };
    }
  }

  /**
   * Busca eventos de auditoria com filtros
   */
  async getEvents(filters: AuditFilters): Promise<AuditEvent[]> {
    const conditions = [];

    if (filters.userId) {
      conditions.push(eq(auditLogs.userId, filters.userId));
    }

    if (filters.action) {
      conditions.push(eq(auditLogs.action, filters.action));
    }

    if (filters.severity) {
      conditions.push(eq(auditLogs.severity, filters.severity));
    }

    if (filters.success !== undefined) {
      conditions.push(eq(auditLogs.success, filters.success));
    }

    if (filters.startDate) {
      conditions.push(gte(auditLogs.timestamp, filters.startDate));
    }

    if (filters.endDate) {
      conditions.push(lte(auditLogs.timestamp, filters.endDate));
    }

    const limit = filters.limit || 100;
    const offset = filters.offset || 0;

    const results = await db
      .select()
      .from(auditLogs)
      .where(conditions.length > 0 ? and(...conditions) : undefined)
      .orderBy(desc(auditLogs.timestamp))
      .limit(limit)
      .offset(offset);

    return results.map((log) => ({
      id: log.id,
      action: log.action as AuditAction,
      severity: log.severity as AuditSeverity,
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
  async getEventById(eventId: string): Promise<AuditEvent | null> {
    const results = await db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.id, eventId))
      .limit(1);

    if (results.length === 0) {
      return null;
    }

    const log = results[0];

    return {
      id: log.id,
      action: log.action as AuditAction,
      severity: log.severity as AuditSeverity,
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
  async countEvents(filters: AuditFilters): Promise<number> {
    const conditions = [];

    if (filters.userId) {
      conditions.push(eq(auditLogs.userId, filters.userId));
    }

    if (filters.action) {
      conditions.push(eq(auditLogs.action, filters.action));
    }

    if (filters.severity) {
      conditions.push(eq(auditLogs.severity, filters.severity));
    }

    if (filters.success !== undefined) {
      conditions.push(eq(auditLogs.success, filters.success));
    }

    if (filters.startDate) {
      conditions.push(gte(auditLogs.timestamp, filters.startDate));
    }

    if (filters.endDate) {
      conditions.push(lte(auditLogs.timestamp, filters.endDate));
    }

    const result = await db
      .select({ count: sql<number>`count(*)` })
      .from(auditLogs)
      .where(conditions.length > 0 ? and(...conditions) : undefined);

    return Number(result[0]?.count || 0);
  }

  /**
   * Exporta eventos de auditoria para análise externa
   * (Para backup, compliance, ou investigação forense)
   */
  async exportEvents(
    userId: string,
    startDate: Date,
    endDate: Date,
    format: 'json' | 'csv' = 'json'
  ): Promise<string> {
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
    const rows = events.map((e) =>
      [
        e.id,
        e.action,
        e.severity,
        e.timestamp.toISOString(),
        e.userId || '',
        e.success,
        e.errorMessage || '',
      ].join(',')
    );

    return [headers.join(','), ...rows].join('\n');
  }

  /**
   * Limpa eventos antigos (para retenção de dados)
   * CUIDADO: Esta operação deve ser usada com extrema cautela
   * e apenas em conformidade com políticas de retenção aprovadas.
   */
  async cleanupOldEvents(olderThan: Date, userId?: string): Promise<number> {
    const conditions = [sql`${auditLogs.timestamp} < ${olderThan}`];

    if (userId) {
      conditions.push(eq(auditLogs.userId, userId));
    }

    // Nota: Em produção, esta operação deve ser:
    // 1. Logada em sistema separado
    // 2. Requerer aprovação de múltiplos administradores
    // 3. Executada em batch para não travar o banco
    
    const result = await db
      .delete(auditLogs)
      .where(and(...conditions));

    // Retorna número aproximado de linhas afetadas
    return 0; // Drizzle não retorna count diretamente
  }
}

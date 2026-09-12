import { db } from '@zero/database';
import { alerts, users, devices } from '@zero/database/schema';
import { eq, and, desc, sql } from 'drizzle-orm';
import { AuditService } from './audit.service.js';
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

export class AlertsService {
  private auditService: AuditService;

  constructor() {
    this.auditService = new AuditService();
  }

  /**
   * Cria um novo alerta de segurança
   */
  async createAlert(input: CreateAlertInput): Promise<AlertResponse> {
    const [newAlert] = await db
      .insert(alerts)
      .values({
        userId: input.userId,
        type: input.type,
        priority: input.priority,
        title: input.title,
        message: input.message,
        deviceId: input.deviceId ?? null,
        metadata: input.metadata ?? null,
        status: 'pending',
      })
      .returning();

    if (!newAlert) {
      throw new Error('Failed to create alert');
    }

    // Log auditoria
    await this.auditService.log({
      userId: input.userId,
      action: 'ALERT_CREATED',
      deviceId: input.deviceId,
      details: {
        alertId: newAlert.id,
        type: input.type,
        priority: input.priority,
      },
    });

    return this.mapToResponse(newAlert);
  }

  /**
   * Cria alerta automático baseado em evento de segurança
   */
  async createSecurityAlert(
    userId: string,
    eventType: string,
    deviceId?: string,
    metadata?: Record<string, unknown>
  ): Promise<AlertResponse> {
    const alertConfig = this.getAlertConfigForEvent(eventType);

    if (!alertConfig) {
      // Evento não gera alerta
      throw new Error(`No alert configuration for event type: ${eventType}`);
    }

    return this.createAlert({
      userId,
      type: alertConfig.type,
      priority: alertConfig.priority,
      title: alertConfig.title,
      message: alertConfig.message(eventType, metadata),
      deviceId,
      metadata,
    });
  }

  /**
   * Lista alertas do usuário
   */
  async getUserAlerts(
    userId: string,
    options: {
      limit?: number;
      offset?: number;
      status?: AlertStatus;
      priority?: AlertPriority;
      unacknowledgedOnly?: boolean;
    } = {}
  ): Promise<AlertResponse[]> {
    const {
      limit = 50,
      offset = 0,
      status,
      priority,
      unacknowledgedOnly,
    } = options;

    const conditions = [eq(alerts.userId, userId)];

    if (status) {
      conditions.push(eq(alerts.status, status));
    }

    if (priority) {
      conditions.push(eq(alerts.priority, priority));
    }

    if (unacknowledgedOnly) {
      conditions.push(eq(alerts.acknowledgedAt, null));
    }

    const userAlerts = await db
      .select()
      .from(alerts)
      .where(and(...conditions))
      .orderBy(desc(alerts.createdAt))
      .limit(limit)
      .offset(offset);

    return userAlerts.map((alert) => this.mapToResponse(alert));
  }

  /**
   * Reconhece um alerta (usuário viu o alerta)
   */
  async acknowledgeAlert(
    alertId: string,
    userId: string
  ): Promise<AlertResponse> {
    const [updatedAlert] = await db
      .update(alerts)
      .set({
        acknowledgedAt: new Date(),
      })
      .where(and(eq(alerts.id, alertId), eq(alerts.userId, userId)))
      .returning();

    if (!updatedAlert) {
      throw new Error('Alert not found or access denied');
    }

    await this.auditService.log({
      userId,
      action: 'ALERT_ACKNOWLEDGED',
      details: { alertId },
    });

    return this.mapToResponse(updatedAlert);
  }

  /**
   * Resolve um alerta (problema foi tratado)
   */
  async resolveAlert(
    alertId: string,
    userId: string
  ): Promise<AlertResponse> {
    const [updatedAlert] = await db
      .update(alerts)
      .set({
        status: 'resolved',
        resolvedAt: new Date(),
      })
      .where(and(eq(alerts.id, alertId), eq(alerts.userId, userId)))
      .returning();

    if (!updatedAlert) {
      throw new Error('Alert not found or access denied');
    }

    await this.auditService.log({
      userId,
      action: 'ALERT_RESOLVED',
      details: { alertId },
    });

    return this.mapToResponse(updatedAlert);
  }

  /**
   * Conta alertas não lidos por prioridade
   */
  async getUnreadAlertsCount(
    userId: string
  ): Promise<{ critical: number; high: number; medium: number; low: number }> {
    const counts = await db
      .select({
        priority: alerts.priority,
        count: sql<number>`COUNT(*)`.mapWith(Number),
      })
      .from(alerts)
      .where(and(eq(alerts.userId, userId), eq(alerts.acknowledgedAt, null)))
      .groupBy(alerts.priority);

    const result = { critical: 0, high: 0, medium: 0, low: 0 };

    for (const row of counts) {
      if (row.priority === 'critical') result.critical = row.count;
      else if (row.priority === 'high') result.high = row.count;
      else if (row.priority === 'medium') result.medium = row.count;
      else if (row.priority === 'low') result.low = row.count;
    }

    return result;
  }

  /**
   * Detecta comportamento anômalo e cria alertas automáticos
   */
  async detectAnomalousBehavior(
    userId: string,
    context: {
      deviceId?: string;
      ipAddress?: string;
      userAgent?: string;
      location?: string;
      eventType: string;
      metadata?: Record<string, unknown>;
    }
  ): Promise<AlertResponse | null> {
    const anomalies = await this.checkForAnomalies(userId, context);

    if (anomalies.length === 0) {
      return null;
    }

    // Cria alerta para a anomalia mais crítica
    const mostCritical = anomalies.sort((a, b) => {
      const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    })[0];

    return this.createAlert({
      userId,
      type: 'anomalous_activity',
      priority: mostCritical.priority,
      title: mostCritical.title,
      message: mostCritical.message,
      deviceId: context.deviceId,
      metadata: {
        anomalies,
        ...context.metadata,
      },
    });
  }

  /**
   * Verifica padrões de anomalia
   */
  private async checkForAnomalies(
    userId: string,
    context: {
      deviceId?: string;
      ipAddress?: string;
      userAgent?: string;
      location?: string;
      eventType: string;
    }
  ): Promise<Array<{ priority: AlertPriority; title: string; message: string }>> {
    const anomalies: Array<{
      priority: AlertPriority;
      title: string;
      message: string;
    }> = [];

    // TODO: Implementar detecção real de anomalias
    // Por enquanto, retorna regras básicas

    // Exemplo: Login de localização muito diferente
    if (context.location) {
      // Lógica futura: comparar com histórico de localizações
      // Se localização > 1000km da última em < 1 hora → alerta crítico
    }

    // Exemplo: Múltiplos dispositivos novos em curto período
    if (context.eventType === 'NEW_DEVICE') {
      // Lógica futura: contar dispositivos criados nas últimas 24h
      // Se > 3 dispositivos → alerta high
    }

    return anomalies;
  }

  /**
   * Configuração de alertas por tipo de evento
   */
  private getAlertConfigForEvent(eventType: string): {
    type: AlertType;
    priority: AlertPriority;
    title: string;
    message: (event: string, metadata?: Record<string, unknown>) => string;
  } | null {
    const configs: Record<
      string,
      {
        type: AlertType;
        priority: AlertPriority;
        title: string;
        message: (event: string, metadata?: Record<string, unknown>) => string;
      }
    > = {
      LOGIN_FAILURE_MULTIPLE: {
        type: 'security',
        priority: 'high',
        title: 'Múltiplas tentativas de login falhas',
        message: (event, meta) =>
          `Detectamos ${meta?.attemptCount ?? 'várias'} tentativas de login falhas. Se não foi você, altere sua senha imediatamente.`,
      },
      NEW_DEVICE: {
        type: 'security',
        priority: 'medium',
        title: 'Novo dispositivo conectado',
        message: () =>
          'Um novo dispositivo foi conectado à sua conta. Se não foi você, revoke o acesso nas configurações de segurança.',
      },
      PASSWORD_CHANGED: {
        type: 'account_change',
        priority: 'high',
        title: 'Senha alterada',
        message: () =>
          'Sua senha foi alterada. Se não foi você, entre em contato com o suporte imediatamente.',
      },
      MFA_DISABLED: {
        type: 'security',
        priority: 'critical',
        title: 'Autenticação de dois fatores desativada',
        message: () =>
          'Seu MFA foi desativado. Sua conta está menos protegida. Ative novamente o mais breve possível.',
      },
      RECOVERY_CODE_USED: {
        type: 'security',
        priority: 'high',
        title: 'Código de recuperação utilizado',
        message: () =>
          'Um código de recuperação foi usado para acessar sua conta. Se não foi você, sua conta pode estar comprometida.',
      },
      SESSION_REVOKED_ALL: {
        type: 'security',
        priority: 'medium',
        title: 'Todas as sessões foram encerradas',
        message: () =>
          'Todas as suas sessões ativas foram encerradas. Você precisará fazer login novamente em seus dispositivos.',
      },
      SUSPICIOUS_DOWNLOAD: {
        type: 'security',
        priority: 'high',
        title: 'Download incomum detectado',
        message: () =>
          'Detectamos um padrão de download incomum. Se não foi você, sua conta pode estar comprometida.',
      },
    };

    return configs[eventType] ?? null;
  }

  /**
   * Mapeia entidade do banco para resposta da API
   */
  private mapToResponse(alert: typeof alerts.$inferSelect): AlertResponse {
    return {
      id: alert.id,
      userId: alert.userId,
      type: alert.type as AlertType,
      priority: alert.priority as AlertPriority,
      status: alert.status as AlertStatus,
      title: alert.title,
      message: alert.message,
      deviceId: alert.deviceId,
      metadata: (alert.metadata as Record<string, unknown>) ?? null,
      createdAt: alert.createdAt,
      acknowledgedAt: alert.acknowledgedAt,
      resolvedAt: alert.resolvedAt,
    };
  }
}

import { db } from '@zero/database';
import { alerts } from '@zero/database/schema';
import { eq, and, desc, sql } from 'drizzle-orm';
import { AuditService } from './audit.service.js';
export class AlertsService {
    auditService;
    constructor() {
        this.auditService = new AuditService();
    }
    /**
     * Cria um novo alerta de segurança
     */
    async createAlert(input) {
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
    async createSecurityAlert(userId, eventType, deviceId, metadata) {
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
    async getUserAlerts(userId, options = {}) {
        const { limit = 50, offset = 0, status, priority, unacknowledgedOnly, } = options;
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
    async acknowledgeAlert(alertId, userId) {
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
    async resolveAlert(alertId, userId) {
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
    async getUnreadAlertsCount(userId) {
        const counts = await db
            .select({
            priority: alerts.priority,
            count: sql `COUNT(*)`.mapWith(Number),
        })
            .from(alerts)
            .where(and(eq(alerts.userId, userId), eq(alerts.acknowledgedAt, null)))
            .groupBy(alerts.priority);
        const result = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const row of counts) {
            if (row.priority === 'critical')
                result.critical = row.count;
            else if (row.priority === 'high')
                result.high = row.count;
            else if (row.priority === 'medium')
                result.medium = row.count;
            else if (row.priority === 'low')
                result.low = row.count;
        }
        return result;
    }
    /**
     * Detecta comportamento anômalo e cria alertas automáticos
     */
    async detectAnomalousBehavior(userId, context) {
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
    async checkForAnomalies(userId, context) {
        const anomalies = [];
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
    getAlertConfigForEvent(eventType) {
        const configs = {
            LOGIN_FAILURE_MULTIPLE: {
                type: 'security',
                priority: 'high',
                title: 'Múltiplas tentativas de login falhas',
                message: (event, meta) => `Detectamos ${meta?.attemptCount ?? 'várias'} tentativas de login falhas. Se não foi você, altere sua senha imediatamente.`,
            },
            NEW_DEVICE: {
                type: 'security',
                priority: 'medium',
                title: 'Novo dispositivo conectado',
                message: () => 'Um novo dispositivo foi conectado à sua conta. Se não foi você, revoke o acesso nas configurações de segurança.',
            },
            PASSWORD_CHANGED: {
                type: 'account_change',
                priority: 'high',
                title: 'Senha alterada',
                message: () => 'Sua senha foi alterada. Se não foi você, entre em contato com o suporte imediatamente.',
            },
            MFA_DISABLED: {
                type: 'security',
                priority: 'critical',
                title: 'Autenticação de dois fatores desativada',
                message: () => 'Seu MFA foi desativado. Sua conta está menos protegida. Ative novamente o mais breve possível.',
            },
            RECOVERY_CODE_USED: {
                type: 'security',
                priority: 'high',
                title: 'Código de recuperação utilizado',
                message: () => 'Um código de recuperação foi usado para acessar sua conta. Se não foi você, sua conta pode estar comprometida.',
            },
            SESSION_REVOKED_ALL: {
                type: 'security',
                priority: 'medium',
                title: 'Todas as sessões foram encerradas',
                message: () => 'Todas as suas sessões ativas foram encerradas. Você precisará fazer login novamente em seus dispositivos.',
            },
            SUSPICIOUS_DOWNLOAD: {
                type: 'security',
                priority: 'high',
                title: 'Download incomum detectado',
                message: () => 'Detectamos um padrão de download incomum. Se não foi você, sua conta pode estar comprometida.',
            },
        };
        return configs[eventType] ?? null;
    }
    /**
     * Mapeia entidade do banco para resposta da API
     */
    mapToResponse(alert) {
        return {
            id: alert.id,
            userId: alert.userId,
            type: alert.type,
            priority: alert.priority,
            status: alert.status,
            title: alert.title,
            message: alert.message,
            deviceId: alert.deviceId,
            metadata: alert.metadata ?? null,
            createdAt: alert.createdAt,
            acknowledgedAt: alert.acknowledgedAt,
            resolvedAt: alert.resolvedAt,
        };
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWxlcnRzLnNlcnZpY2UuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi8uLi8uLi8uLi9wYWNrYWdlcy9hdXRoL3NyYy9zZXJ2aWNlcy9hbGVydHMuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQUUsRUFBRSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFDcEMsT0FBTyxFQUFFLE1BQU0sRUFBa0IsTUFBTSx1QkFBdUIsQ0FBQztBQUMvRCxPQUFPLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxJQUFJLEVBQUUsR0FBRyxFQUFFLE1BQU0sYUFBYSxDQUFDO0FBQ2pELE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxvQkFBb0IsQ0FBQztBQTRCbEQsTUFBTSxPQUFPLGFBQWE7SUFDaEIsWUFBWSxDQUFlO0lBRW5DO1FBQ0UsSUFBSSxDQUFDLFlBQVksR0FBRyxJQUFJLFlBQVksRUFBRSxDQUFDO0lBQ3pDLENBQUM7SUFFRDs7T0FFRztJQUNILEtBQUssQ0FBQyxXQUFXLENBQUMsS0FBdUI7UUFDdkMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxHQUFHLE1BQU0sRUFBRTthQUN4QixNQUFNLENBQUMsTUFBTSxDQUFDO2FBQ2QsTUFBTSxDQUFDO1lBQ04sTUFBTSxFQUFFLEtBQUssQ0FBQyxNQUFNO1lBQ3BCLElBQUksRUFBRSxLQUFLLENBQUMsSUFBSTtZQUNoQixRQUFRLEVBQUUsS0FBSyxDQUFDLFFBQVE7WUFDeEIsS0FBSyxFQUFFLEtBQUssQ0FBQyxLQUFLO1lBQ2xCLE9BQU8sRUFBRSxLQUFLLENBQUMsT0FBTztZQUN0QixRQUFRLEVBQUUsS0FBSyxDQUFDLFFBQVEsSUFBSSxJQUFJO1lBQ2hDLFFBQVEsRUFBRSxLQUFLLENBQUMsUUFBUSxJQUFJLElBQUk7WUFDaEMsTUFBTSxFQUFFLFNBQVM7U0FDbEIsQ0FBQzthQUNELFNBQVMsRUFBRSxDQUFDO1FBRWYsSUFBSSxDQUFDLFFBQVEsRUFBRSxDQUFD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QyxRQUFRO1lBQ3hCLFFBQVEsRUFBRyxLQUFLLENBQUMsUUFBb0MsSUFBSSxJQUFJO1lBQzdELFNBQVMsRUFBRSxLQUFLLENBQUMsU0FBUztZQUMxQixjQUFjLEVBQUUsS0FBSyxDQUFDLGNBQWM7WUFDcEMsVUFBVSxFQUFFLEtBQUssQ0FBQyxVQUFVO1NBQzdCLENBQUM7SUFDSixDQUFDO0NBQ0YiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBkYiB9IGZyb20gJ0B6ZXJvL2RhdGFiYXNlJztcbmltcG9ydCB7IGFsZXJ0cywgdXNlcnMsIGRldmljZXMgfSBmcm9tICdAemVyby9kYXRhYmFzZS9zY2hlbWEnO1xuaW1wb3J0IHsgZXEsIGFuZCwgZGVzYywgc3FsIH0gZnJvbSAnZHJpenpsZS1vcm0nO1xuaW1wb3J0IHsgQXVkaXRTZXJ2aWNlIH0gZnJvbSAnLi9hdWRpdC5zZXJ2aWNlLmpzJztcbmltcG9ydCB0eXBlIHsgQWxlcnRUeXBlLCBBbGVydFByaW9yaXR5LCBBbGVydFN0YXR1cyB9IGZyb20gJy4uL3R5cGVzL2FsZXJ0cy5qcyc7XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlQWxlcnRJbnB1dCB7XG4gIHVzZXJJZDogc3RyaW5nO1xuICB0eXBlOiBBbGVydFR5cGU7XG4gIHByaW9yaXR5OiBBbGVydFByaW9yaXR5O1xuICB0aXRsZTogc3RyaW5nO1xuICBtZXNzYWdlOiBzdHJpbmc7XG4gIGRldmljZUlkPzogc3RyaW5nO1xuICBtZXRhZGF0YT86IFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFsZXJ0UmVzcG9uc2Uge1xuICBpZDogc3RyaW5nO1xuICB1c2VySWQ6IHN0cmluZztcbiAgdHlwZTogQWxlcnRUeXBlO1xuICBwcmlvcml0eTogQWxlcnRQcmlvcml0eTtcbiAgc3RhdHVzOiBBbGVydFN0YXR1cztcbiAgdGl0bGU6IHN0cmluZztcbiAgbWVzc2FnZTogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nIHwgbnVsbDtcbiAgbWV0YWRhdGE6IFJlY29yZDxzdHJpbmcsIHVua25vd24+IHwgbnVsbDtcbiAgY3JlYXRlZEF0OiBEYXRlO1xuICBhY2tub3dsZWRnZWRBdDogRGF0ZSB8IG51bGw7XG4gIHJlc29sdmVkQXQ6IERhdGUgfCBudWxsO1xufVxuXG5leHBvcnQgY2xhc3MgQWxlcnRzU2VydmljZSB7XG4gIHByaXZhdGUgYXVkaXRTZXJ2aWNlOiBBdWRpdFNlcnZpY2U7XG5cbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy5hdWRpdFNlcnZpY2UgPSBuZXcgQXVkaXRTZXJ2aWNlKCk7XG4gIH1cblxuICAvKipcbiAgICogQ3JpYSB1bSBub3ZvIGFsZXJ0YSBkZSBzZWd1cmFuw6dhXG4gICAqL1xuICBhc3luYyBjcmVhdGVBbGVydChpbnB1dDogQ3JlYXRlQWxlcnRJbnB1dCk6IFByb21pc2U8QWxlcnRSZXNwb25zZT4ge1xuICAgIGNvbnN0IFtuZXdBbGVydF0gPSBhd2FpdCBkYlxuICAgICAgLmluc2VydChhbGVydHMpXG4gICAgICAudmFsdWVzKHtcbiAgICAgICAgdXNlcklkOiBpbnB1dC51c2VySWQsXG4gICAgICAgIHR5cGU6IGlucHV0LnR5cGUsXG4gICAgICAgIHByaW9yaXR5OiBpbnB1dC5wcmlvcml0eSxcbiAgICAgICAgdGl0bGU6IGlucHV0LnRpdGxlLFxuICAgICAgICBtZXNzYWdlOiBpbnB1dC5tZXNzYWdlLFxuICAgICAgICBkZXZpY2VJZDogaW5wdXQuZGV2aWNlSWQgPz8gbnVsbCxcbiAgICAgICAgbWV0YWRhdGE6IGlucHV0Lm1ldGFkYXRhID8/IG51bGwsXG4gICAgICAgIHN0YXR1czogJ3BlbmRpbmcnLFxuICAgICAgfSlcbiAgICAgIC5yZXR1cm5pbmcoKTtcblxuICAgIGlmICghbmV3QWxlcnQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignRmFpbGVkIHRvIGNyZWF0ZSBhbGVydCcpO1xuICAgIH1cblxuICAgIC8vIExvZyBhdWRpdG9yaWFcbiAgICBhd2FpdCB0aGlzLmF1ZGl0U2VydmljZS5sb2coe1xuICAgICAgdXNlcklkOiBpbnB1dC51c2VySWQsXG4gICAgICBhY3Rpb246ICdBTEVSVF9DUkVBVEVEJyxcbiAgICAgIGRldmljZUlkOiBpbnB1dC5kZXZpY2VJZCxcbiAgICAgIGRldGFpbHM6IHtcbiAgICAgICAgYWxlcnRJZDogbmV3QWxlcnQuaWQsXG4gICAgICAgIHR5cGU6IGlucHV0LnR5cGUsXG4gICAgICAgIHByaW9yaXR5OiBpbnB1dC5wcmlvcml0eSxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICByZXR1cm4gdGhpcy5tYXBUb1Jlc3BvbnNlKG5ld0FsZXJ0KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDcmlhIGFsZXJ0YSBhdXRvbcOhdGljbyBiYXNlYWRvIGVtIGV2ZW50byBkZSBzZWd1cmFuw6dhXG4gICAqL1xuICBhc3luYyBjcmVhdGVTZWN1cml0eUFsZXJ0KFxuICAgIHVzZXJJZDogc3RyaW5nLFxuICAgIGV2ZW50VHlwZTogc3RyaW5nLFxuICAgIGRldmljZUlkPzogc3RyaW5nLFxuICAgIG1ldGFkYXRhPzogUmVjb3JkPHN0cmluZywgdW5rbm93bj5cbiAgKTogUHJvbWlzZTxBbGVydFJlc3BvbnNlPiB7XG4gICAgY29uc3QgYWxlcnRDb25maWcgPSB0aGlzLmdldEFsZXJ0Q29uZmlnRm9yRXZlbnQoZXZlbnRUeXBlKTtcblxuICAgIGlmICghYWxlcnRDb25maWcpIHtcbiAgICAgIC8vIEV2ZW50byBuw6NvIGdlcmEgYWxlcnRhXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYE5vIGFsZXJ0IGNvbmZpZ3VyYXRpb24gZm9yIGV2ZW50IHR5cGU6ICR7ZXZlbnRUeXBlfWApO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLmNyZWF0ZUFsZXJ0KHtcbiAgICAgIHVzZXJJZCxcbiAgICAgIHR5cGU6IGFsZXJ0Q29uZmlnLnR5cGUsXG4gICAgICBwcmlvcml0eTogYWxlcnRDb25maWcucHJpb3JpdHksXG4gICAgICB0aXRsZTogYWxlcnRDb25maWcudGl0bGUsXG4gICAgICBtZXNzYWdlOiBhbGVydENvbmZpZy5tZXNzYWdlKGV2ZW50VHlwZSwgbWV0YWRhdGEpLFxuICAgICAgZGV2aWNlSWQsXG4gICAgICBtZXRhZGF0YSxcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBMaXN0YSBhbGVydGFzIGRvIHVzdcOhcmlvXG4gICAqL1xuICBhc3luYyBnZXRVc2VyQWxlcnRzKFxuICAgIHVzZXJJZDogc3RyaW5nLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIGxpbWl0PzogbnVtYmVyO1xuICAgICAgb2Zmc2V0PzogbnVtYmVyO1xuICAgICAgc3RhdHVzPzogQWxlcnRTdGF0dXM7XG4gICAgICBwcmlvcml0eT86IEFsZXJ0UHJpb3JpdHk7XG4gICAgICB1bmFja25vd2xlZGdlZE9ubHk/OiBib29sZWFuO1xuICAgIH0gPSB7fVxuICApOiBQcm9taXNlPEFsZXJ0UmVzcG9uc2VbXT4ge1xuICAgIGNvbnN0IHtcbiAgICAgIGxpbWl0ID0gNTAsXG4gICAgICBvZmZzZXQgPSAwLFxuICAgICAgc3RhdHVzLFxuICAgICAgcHJpb3JpdHksXG4gICAgICB1bmFja25vd2xlZGdlZE9ubHksXG4gICAgfSA9IG9wdGlvbnM7XG5cbiAgICBjb25zdCBjb25kaXRpb25zID0gW2VxKGFsZXJ0cy51c2VySWQsIHVzZXJJZCldO1xuXG4gICAgaWYgKHN0YXR1cykge1xuICAgICAgY29uZGl0aW9ucy5wdXNoKGVxKGFsZXJ0cy5zdGF0dXMsIHN0YXR1cykpO1xuICAgIH1cblxuICAgIGlmIChwcmlvcml0eSkge1xuICAgICAgY29uZGl0aW9ucy5wdXNoKGVxKGFsZXJ0cy5wcmlvcml0eSwgcHJpb3JpdHkpKTtcbiAgICB9XG5cbiAgICBpZiAodW5hY2tub3dsZWRnZWRPbmx5KSB7XG4gICAgICBjb25kaXRpb25zLnB1c2goZXEoYWxlcnRzLmFja25vd2xlZGdlZEF0LCBudWxsKSk7XG4gICAgfVxuXG4gICAgY29uc3QgdXNlckFsZXJ0cyA9IGF3YWl0IGRiXG4gICAgICAuc2VsZWN0KClcbiAgICAgIC5mcm9tKGFsZXJ0cylcbiAgICAgIC53aGVyZShhbmQoLi4uY29uZGl0aW9ucykpXG4gICAgICAub3JkZXJCeShkZXNjKGFsZXJ0cy5jcmVhdGVkQXQpKVxuICAgICAgLmxpbWl0KGxpbWl0KVxuICAgICAgLm9mZnNldChvZmZzZXQpO1xuXG4gICAgcmV0dXJuIHVzZXJBbGVydHMubWFwKChhbGVydCkgPT4gdGhpcy5tYXBUb1Jlc3BvbnNlKGFsZXJ0KSk7XG4gIH1cblxuICAvKipcbiAgICogUmVjb25oZWNlIHVtIGFsZXJ0YSAodXN1w6FyaW8gdml1IG8gYWxlcnRhKVxuICAgKi9cbiAgYXN5bmMgYWNrbm93bGVkZ2VBbGVydChcbiAgICBhbGVydElkOiBzdHJpbmcsXG4gICAgdXNlcklkOiBzdHJpbmdcbiAgKTogUHJvbWlzZTxBbGVydFJlc3BvbnNlPiB7XG4gICAgY29uc3QgW3VwZGF0ZWRBbGVydF0gPSBhd2FpdCBkYlxuICAgICAgLnVwZGF0ZShhbGVydHMpXG4gICAgICAuc2V0KHtcbiAgICAgICAgYWNrbm93bGVkZ2VkQXQ6IG5ldyBEYXRlKCksXG4gICAgICB9KVxuICAgICAgLndoZXJlKGFuZChlcShhbGVydHMuaWQsIGFsZXJ0SWQpLCBlcShhbGVydHMudXNlcklkLCB1c2VySWQpKSlcbiAgICAgIC5yZXR1cm5pbmcoKTtcblxuICAgIGlmICghdXBkYXRlZEFsZXJ0KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0FsZXJ0IG5vdCBmb3VuZCBvciBhY2Nlc3MgZGVuaWVkJyk7XG4gICAgfVxuXG4gICAgYXdhaXQgdGhpcy5hdWRpdFNlcnZpY2UubG9nKHtcbiAgICAgIHVzZXJJZCxcbiAgICAgIGFjdGlvbjogJ0FMRVJUX0FDS05PV0xFREdFRCcsXG4gICAgICBkZXRhaWxzOiB7IGFsZXJ0SWQgfSxcbiAgICB9KTtcblxuICAgIHJldHVybiB0aGlzLm1hcFRvUmVzcG9uc2UodXBkYXRlZEFsZXJ0KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXNvbHZlIHVtIGFsZXJ0YSAocHJvYmxlbWEgZm9pIHRyYXRhZG8pXG4gICAqL1xuICBhc3luYyByZXNvbHZlQWxlcnQoXG4gICAgYWxlcnRJZDogc3RyaW5nLFxuICAgIHVzZXJJZDogc3RyaW5nXG4gICk6IFByb21pc2U8QWxlcnRSZXNwb25zZT4ge1xuICAgIGNvbnN0IFt1cGRhdGVkQWxlcnRdID0gYXdhaXQgZGJcbiAgICAgIC51cGRhdGUoYWxlcnRzKVxuICAgICAgLnNldCh7XG4gICAgICAgIHN0YXR1czogJ3Jlc29sdmVkJyxcbiAgICAgICAgcmVzb2x2ZWRBdDogbmV3IERhdGUoKSxcbiAgICAgIH0pXG4gICAgICAud2hlcmUoYW5kKGVxKGFsZXJ0cy5pZCwgYWxlcnRJZCksIGVxKGFsZXJ0cy51c2VySWQsIHVzZXJJZCkpKVxuICAgICAgLnJldHVybmluZygpO1xuXG4gICAgaWYgKCF1cGRhdGVkQWxlcnQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQWxlcnQgbm90IGZvdW5kIG9yIGFjY2VzcyBkZW5pZWQnKTtcbiAgICB9XG5cbiAgICBhd2FpdCB0aGlzLmF1ZGl0U2VydmljZS5sb2coe1xuICAgICAgdXNlcklkLFxuICAgICAgYWN0aW9uOiAnQUxFUlRfUkVTT0xWRUQnLFxuICAgICAgZGV0YWlsczogeyBhbGVydElkIH0sXG4gICAgfSk7XG5cbiAgICByZXR1cm4gdGhpcy5tYXBUb1Jlc3BvbnNlKHVwZGF0ZWRBbGVydCk7XG4gIH1cblxuICAvKipcbiAgICogQ29udGEgYWxlcnRhcyBuw6NvIGxpZG9zIHBvciBwcmlvcmlkYWRlXG4gICAqL1xuICBhc3luYyBnZXRVbnJlYWRBbGVydHNDb3VudChcbiAgICB1c2VySWQ6IHN0cmluZ1xuICApOiBQcm9taXNlPHsgY3JpdGljYWw6IG51bWJlcjsgaGlnaDogbnVtYmVyOyBtZWRpdW06IG51bWJlcjsgbG93OiBudW1iZXIgfT4ge1xuICAgIGNvbnN0IGNvdW50cyA9IGF3YWl0IGRiXG4gICAgICAuc2VsZWN0KHtcbiAgICAgICAgcHJpb3JpdHk6IGFsZXJ0cy5wcmlvcml0eSxcbiAgICAgICAgY291bnQ6IHNxbDxudW1iZXI+YENPVU5UKCopYC5tYXBXaXRoKE51bWJlciksXG4gICAgICB9KVxuICAgICAgLmZyb20oYWxlcnRzKVxuICAgICAgLndoZXJlKGFuZChlcShhbGVydHMudXNlcklkLCB1c2VySWQpLCBlcShhbGVydHMuYWNrbm93bGVkZ2VkQXQsIG51bGwpKSlcbiAgICAgIC5ncm91cEJ5KGFsZXJ0cy5wcmlvcml0eSk7XG5cbiAgICBjb25zdCByZXN1bHQgPSB7IGNyaXRpY2FsOiAwLCBoaWdoOiAwLCBtZWRpdW06IDAsIGxvdzogMCB9O1xuXG4gICAgZm9yIChjb25zdCByb3cgb2YgY291bnRzKSB7XG4gICAgICBpZiAocm93LnByaW9yaXR5ID09PSAnY3JpdGljYWwnKSByZXN1bHQuY3JpdGljYWwgPSByb3cuY291bnQ7XG4gICAgICBlbHNlIGlmIChyb3cucHJpb3JpdHkgPT09ICdoaWdoJykgcmVzdWx0LmhpZ2ggPSByb3cuY291bnQ7XG4gICAgICBlbHNlIGlmIChyb3cucHJpb3JpdHkgPT09ICdtZWRpdW0nKSByZXN1bHQubWVkaXVtID0gcm93LmNvdW50O1xuICAgICAgZWxzZSBpZiAocm93LnByaW9yaXR5ID09PSAnbG93JykgcmVzdWx0LmxvdyA9IHJvdy5jb3VudDtcbiAgICB9XG5cbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLyoqXG4gICAqIERldGVjdGEgY29tcG9ydGFtZW50byBhbsO0bWFsbyBlIGNyaWEgYWxlcnRhcyBhdXRvbcOhdGljb3NcbiAgICovXG4gIGFzeW5jIGRldGVjdEFub21hbG91c0JlaGF2aW9yKFxuICAgIHVzZXJJZDogc3RyaW5nLFxuICAgIGNvbnRleHQ6IHtcbiAgICAgIGRldmljZUlkPzogc3RyaW5nO1xuICAgICAgaXBBZGRyZXNzPzogc3RyaW5nO1xuICAgICAgdXNlckFnZW50Pzogc3RyaW5nO1xuICAgICAgbG9jYXRpb24/OiBzdHJpbmc7XG4gICAgICBldmVudFR5cGU6IHN0cmluZztcbiAgICAgIG1ldGFkYXRhPzogUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG4gICAgfVxuICApOiBQcm9taXNlPEFsZXJ0UmVzcG9uc2UgfCBudWxsPiB7XG4gICAgY29uc3QgYW5vbWFsaWVzID0gYXdhaXQgdGhpcy5jaGVja0ZvckFub21hbGllcyh1c2VySWQsIGNvbnRleHQpO1xuXG4gICAgaWYgKGFub21hbGllcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cblxuICAgIC8vIENyaWEgYWxlcnRhIHBhcmEgYSBhbm9tYWxpYSBtYWlzIGNyw610aWNhXG4gICAgY29uc3QgbW9zdENyaXRpY2FsID0gYW5vbWFsaWVzLnNvcnQoKGEsIGIpID0+IHtcbiAgICAgIGNvbnN0IHByaW9yaXR5T3JkZXIgPSB7IGNyaXRpY2FsOiA0LCBoaWdoOiAzLCBtZWRpdW06IDIsIGxvdzogMSB9O1xuICAgICAgcmV0dXJuIHByaW9yaXR5T3JkZXJbYi5wcmlvcml0eV0gLSBwcmlvcml0eU9yZGVyW2EucHJpb3JpdHldO1xuICAgIH0pWzBdO1xuXG4gICAgcmV0dXJuIHRoaXMuY3JlYXRlQWxlcnQoe1xuICAgICAgdXNlcklkLFxuICAgICAgdHlwZTogJ2Fub21hbG91c19hY3Rpdml0eScsXG4gICAgICBwcmlvcml0eTogbW9zdENyaXRpY2FsLnByaW9yaXR5LFxuICAgICAgdGl0bGU6IG1vc3RDcml0aWNhbC50aXRsZSxcbiAgICAgIG1lc3NhZ2U6IG1vc3RDcml0aWNhbC5tZXNzYWdlLFxuICAgICAgZGV2aWNlSWQ6IGNvbnRleHQuZGV2aWNlSWQsXG4gICAgICBtZXRhZGF0YToge1xuICAgICAgICBhbm9tYWxpZXMsXG4gICAgICAgIC4uLmNvbnRleHQubWV0YWRhdGEsXG4gICAgICB9LFxuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFZlcmlmaWNhIHBhZHLDtWVzIGRlIGFub21hbGlhXG4gICAqL1xuICBwcml2YXRlIGFzeW5jIGNoZWNrRm9yQW5vbWFsaWVzKFxuICAgIHVzZXJJZDogc3RyaW5nLFxuICAgIGNvbnRleHQ6IHtcbiAgICAgIGRldmljZUlkPzogc3RyaW5nO1xuICAgICAgaXBBZGRyZXNzPzogc3RyaW5nO1xuICAgICAgdXNlckFnZW50Pzogc3RyaW5nO1xuICAgICAgbG9jYXRpb24/OiBzdHJpbmc7XG4gICAgICBldmVudFR5cGU6IHN0cmluZztcbiAgICB9XG4gICk6IFByb21pc2U8QXJyYXk8eyBwcmlvcml0eTogQWxlcnRQcmlvcml0eTsgdGl0bGU6IHN0cmluZzsgbWVzc2FnZTogc3RyaW5nIH0+PiB7XG4gICAgY29uc3QgYW5vbWFsaWVzOiBBcnJheTx7XG4gICAgICBwcmlvcml0eTogQWxlcnRQcmlvcml0eTtcbiAgICAgIHRpdGxlOiBzdHJpbmc7XG4gICAgICBtZXNzYWdlOiBzdHJpbmc7XG4gICAgfT4gPSBbXTtcblxuICAgIC8vIFRPRE86IEltcGxlbWVudGFyIGRldGVjw6fDo28gcmVhbCBkZSBhbm9tYWxpYXNcbiAgICAvLyBQb3IgZW5xdWFudG8sIHJldG9ybmEgcmVncmFzIGLDoXNpY2FzXG5cbiAgICAvLyBFeGVtcGxvOiBMb2dpbiBkZSBsb2NhbGl6YcOnw6NvIG11aXRvIGRpZmVyZW50ZVxuICAgIGlmIChjb250ZXh0LmxvY2F0aW9uKSB7XG4gICAgICAvLyBMw7NnaWNhIGZ1dHVyYTogY29tcGFyYXIgY29tIGhpc3TDs3JpY28gZGUgbG9jYWxpemHDp8O1ZXNcbiAgICAgIC8vIFNlIGxvY2FsaXphw6fDo28gPiAxMDAwa20gZGEgw7psdGltYSBlbSA8IDEgaG9yYSDihpIgYWxlcnRhIGNyw610aWNvXG4gICAgfVxuXG4gICAgLy8gRXhlbXBsbzogTcO6bHRpcGxvcyBkaXNwb3NpdGl2b3Mgbm92b3MgZW0gY3VydG8gcGVyw61vZG9cbiAgICBpZiAoY29udGV4dC5ldmVudFR5cGUgPT09ICdORVdfREVWSUNFJykge1xuICAgICAgLy8gTMOzZ2ljYSBmdXR1cmE6IGNvbnRhciBkaXNwb3NpdGl2b3MgY3JpYWRvcyBuYXMgw7psdGltYXMgMjRoXG4gICAgICAvLyBTZSA+IDMgZGlzcG9zaXRpdm9zIOKGkiBhbGVydGEgaGlnaFxuICAgIH1cblxuICAgIHJldHVybiBhbm9tYWxpZXM7XG4gIH1cblxuICAvKipcbiAgICogQ29uZmlndXJhw6fDo28gZGUgYWxlcnRhcyBwb3IgdGlwbyBkZSBldmVudG9cbiAgICovXG4gIHByaXZhdGUgZ2V0QWxlcnRDb25maWdGb3JFdmVudChldmVudFR5cGU6IHN0cmluZyk6IHtcbiAgICB0eXBlOiBBbGVydFR5cGU7XG4gICAgcHJpb3JpdHk6IEFsZXJ0UHJpb3JpdHk7XG4gICAgdGl0bGU6IHN0cmluZztcbiAgICBtZXNzYWdlOiAoZXZlbnQ6IHN0cmluZywgbWV0YWRhdGE/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPikgPT4gc3RyaW5nO1xuICB9IHwgbnVsbCB7XG4gICAgY29uc3QgY29uZmlnczogUmVjb3JkPFxuICAgICAgc3RyaW5nLFxuICAgICAge1xuICAgICAgICB0eXBlOiBBbGVydFR5cGU7XG4gICAgICAgIHByaW9yaXR5OiBBbGVydFByaW9yaXR5O1xuICAgICAgICB0aXRsZTogc3RyaW5nO1xuICAgICAgICBtZXNzYWdlOiAoZXZlbnQ6IHN0cmluZywgbWV0YWRhdGE/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPikgPT4gc3RyaW5nO1xuICAgICAgfVxuICAgID4gPSB7XG4gICAgICBMT0dJTl9GQUlMVVJFX01VTFRJUExFOiB7XG4gICAgICAgIHR5cGU6ICdzZWN1cml0eScsXG4gICAgICAgIHByaW9yaXR5OiAnaGlnaCcsXG4gICAgICAgIHRpdGxlOiAnTcO6bHRpcGxhcyB0ZW50YXRpdmFzIGRlIGxvZ2luIGZhbGhhcycsXG4gICAgICAgIG1lc3NhZ2U6IChldmVudCwgbWV0YSkgPT5cbiAgICAgICAgICBgRGV0ZWN0YW1vcyAke21ldGE/LmF0dGVtcHRDb3VudCA/PyAndsOhcmlhcyd9IHRlbnRhdGl2YXMgZGUgbG9naW4gZmFsaGFzLiBTZSBuw6NvIGZvaSB2b2PDqiwgYWx0ZXJlIHN1YSBzZW5oYSBpbWVkaWF0YW1lbnRlLmAsXG4gICAgICB9LFxuICAgICAgTkVXX0RFVklDRToge1xuICAgICAgICB0eXBlOiAnc2VjdXJpdHknLFxuICAgICAgICBwcmlvcml0eTogJ21lZGl1bScsXG4gICAgICAgIHRpdGxlOiAnTm92byBkaXNwb3NpdGl2byBjb25lY3RhZG8nLFxuICAgICAgICBtZXNzYWdlOiAoKSA9PlxuICAgICAgICAgICdVbSBub3ZvIGRpc3Bvc2l0aXZvIGZvaSBjb25lY3RhZG8gw6Agc3VhIGNvbnRhLiBTZSBuw6NvIGZvaSB2b2PDqiwgcmV2b2tlIG8gYWNlc3NvIG5hcyBjb25maWd1cmHDp8O1ZXMgZGUgc2VndXJhbsOnYS4nLFxuICAgICAgfSxcbiAgICAgIFBBU1NXT1JEX0NIQU5HRUQ6IHtcbiAgICAgICAgdHlwZTogJ2FjY291bnRfY2hhbmdlJyxcbiAgICAgICAgcHJpb3JpdHk6ICdoaWdoJyxcbiAgICAgICAgdGl0bGU6ICdTZW5oYSBhbHRlcmFkYScsXG4gICAgICAgIG1lc3NhZ2U6ICgpID0+XG4gICAgICAgICAgJ1N1YSBzZW5oYSBmb2kgYWx0ZXJhZGEuIFNlIG7Do28gZm9pIHZvY8OqLCBlbnRyZSBlbSBjb250YXRvIGNvbSBvIHN1cG9ydGUgaW1lZGlhdGFtZW50ZS4nLFxuICAgICAgfSxcbiAgICAgIE1GQV9ESVNBQkxFRDoge1xuICAgICAgICB0eXBlOiAnc2VjdXJpdHknLFxuICAgICAgICBwcmlvcml0eTogJ2NyaXRpY2FsJyxcbiAgICAgICAgdGl0bGU6ICdBdXRlbnRpY2HDp8OjbyBkZSBkb2lzIGZhdG9yZXMgZGVzYXRpdmFkYScsXG4gICAgICAgIG1lc3NhZ2U6ICgpID0+XG4gICAgICAgICAgJ1NldSBNRkEgZm9pIGRlc2F0aXZhZG8uIFN1YSBjb250YSBlc3TDoSBtZW5vcyBwcm90ZWdpZGEuIEF0aXZlIG5vdmFtZW50ZSBvIG1haXMgYnJldmUgcG9zc8OtdmVsLicsXG4gICAgICB9LFxuICAgICAgUkVDT1ZFUllfQ09ERV9VU0VEOiB7XG4gICAgICAgIHR5cGU6ICdzZWN1cml0eScsXG4gICAgICAgIHByaW9yaXR5OiAnaGlnaCcsXG4gICAgICAgIHRpdGxlOiAnQ8OzZGlnbyBkZSByZWN1cGVyYcOnw6NvIHV0aWxpemFkbycsXG4gICAgICAgIG1lc3NhZ2U6ICgpID0+XG4gICAgICAgICAgJ1VtIGPDs2RpZ28gZGUgcmVjdXBlcmHDp8OjbyBmb2kgdXNhZG8gcGFyYSBhY2Vzc2FyIHN1YSBjb250YS4gU2UgbsOjbyBmb2kgdm9jw6osIHN1YSBjb250YSBwb2RlIGVzdGFyIGNvbXByb21ldGlkYS4nLFxuICAgICAgfSxcbiAgICAgIFNFU1NJT05fUkVWT0tFRF9BTEw6IHtcbiAgICAgICAgdHlwZTogJ3NlY3VyaXR5JyxcbiAgICAgICAgcHJpb3JpdHk6ICdtZWRpdW0nLFxuICAgICAgICB0aXRsZTogJ1RvZGFzIGFzIHNlc3PDtWVzIGZvcmFtIGVuY2VycmFkYXMnLFxuICAgICAgICBtZXNzYWdlOiAoKSA9PlxuICAgICAgICAgICdUb2RhcyBhcyBzdWFzIHNlc3PDtWVzIGF0aXZhcyBmb3JhbSBlbmNlcnJhZGFzLiBWb2PDqiBwcmVjaXNhcsOhIGZhemVyIGxvZ2luIG5vdmFtZW50ZSBlbSBzZXVzIGRpc3Bvc2l0aXZvcy4nLFxuICAgICAgfSxcbiAgICAgIFNVU1BJQ0lPVVNfRE9XTkxPQUQ6IHtcbiAgICAgICAgdHlwZTogJ3NlY3VyaXR5JyxcbiAgICAgICAgcHJpb3JpdHk6ICdoaWdoJyxcbiAgICAgICAgdGl0bGU6ICdEb3dubG9hZCBpbmNvbXVtIGRldGVjdGFkbycsXG4gICAgICAgIG1lc3NhZ2U6ICgpID0+XG4gICAgICAgICAgJ0RldGVjdGFtb3MgdW0gcGFkcsOjbyBkZSBkb3dubG9hZCBpbmNvbXVtLiBTZSBuw6NvIGZvaSB2b2PDqiwgc3VhIGNvbnRhIHBvZGUgZXN0YXIgY29tcHJvbWV0aWRhLicsXG4gICAgICB9LFxuICAgIH07XG5cbiAgICByZXR1cm4gY29uZmlnc1tldmVudFR5cGVdID8/IG51bGw7XG4gIH1cblxuICAvKipcbiAgICogTWFwZWlhIGVudGlkYWRlIGRvIGJhbmNvIHBhcmEgcmVzcG9zdGEgZGEgQVBJXG4gICAqL1xuICBwcml2YXRlIG1hcFRvUmVzcG9uc2UoYWxlcnQ6IHR5cGVvZiBhbGVydHMuJGluZmVyU2VsZWN0KTogQWxlcnRSZXNwb25zZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBhbGVydC5pZCxcbiAgICAgIHVzZXJJZDogYWxlcnQudXNlcklkLFxuICAgICAgdHlwZTogYWxlcnQudHlwZSBhcyBBbGVydFR5cGUsXG4gICAgICBwcmlvcml0eTogYWxlcnQucHJpb3JpdHkgYXMgQWxlcnRQcmlvcml0eSxcbiAgICAgIHN0YXR1czogYWxlcnQuc3RhdHVzIGFzIEFsZXJ0U3RhdHVzLFxuICAgICAgdGl0bGU6IGFsZXJ0LnRpdGxlLFxuICAgICAgbWVzc2FnZTogYWxlcnQubWVzc2FnZSxcbiAgICAgIGRldmljZUlkOiBhbGVydC5kZXZpY2VJZCxcbiAgICAgIG1ldGFkYXRhOiAoYWxlcnQubWV0YWRhdGEgYXMgUmVjb3JkPHN0cmluZywgdW5rbm93bj4pID8/IG51bGwsXG4gICAgICBjcmVhdGVkQXQ6IGFsZXJ0LmNyZWF0ZWRBdCxcbiAgICAgIGFja25vd2xlZGdlZEF0OiBhbGVydC5hY2tub3dsZWRnZWRBdCxcbiAgICAgIHJlc29sdmVkQXQ6IGFsZXJ0LnJlc29sdmVkQXQsXG4gICAgfTtcbiAgfVxufVxuIl19
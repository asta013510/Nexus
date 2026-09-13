export const __esModule: boolean;
export class AuditService {
    constructor(pool: any);
    pool: any;
    /**
     * Registra um evento de auditoria
     * SECURITY: Nunca logar dados sensíveis (senhas, tokens, chaves)
     */
    log(event: any): Promise<`${string}-${string}-${string}-${string}-${string}`>;
    /**
     * Remove dados sensíveis da metadata
     */
    sanitizeMetadata(metadata: any): {};
    /**
     * Busca eventos de auditoria por usuário
     */
    getUserEvents(userId: any, limit?: number, offset?: number): Promise<any>;
    /**
     * Busca eventos de auditoria por sessão
     */
    getSessionEvents(sessionId: any, limit?: number): Promise<any>;
    /**
     * Busca eventos suspeitos (risk_level = high ou critical)
     */
    getSuspiciousEvents(limit?: number): Promise<any>;
    /**
     * Converte row do banco para AuditEvent
     */
    rowToEvent(row: any): {
        id: any;
        eventType: any;
        userId: any;
        sessionId: any;
        deviceId: any;
        ipAddress: any;
        userAgent: any;
        timestamp: any;
        success: any;
        metadata: any;
        riskLevel: any;
    };
    /**
     * Detecta atividade suspeita baseada em padrões
     * - Múltiplas falhas de login
     * - Login de localização incomum
     * - Múltiplos dispositivos em curto período
     */
    detectSuspiciousActivity(userId: any, context: any): Promise<boolean>;
}
//# sourceMappingURL=audit.service.d.ts.map
"use strict";
/**
 * Serviço WebAuthn/Passkeys (Placeholder)
 *
 * NOTA: Esta é uma implementação inicial/planning.
 * WebAuthn completo requer:
 * - Integração com @simplewebauthn/server
 * - Geração de challenges criptográficas
 * - Validação de attestation/assertion responses
 * - Armazenamento seguro de credential IDs e public keys
 *
 * SECURITY NOTES:
 * - Usar apenas como fator ADICIONAL, nunca único
 * - Requerer MFA TOTP como fallback
 * - Validar origem (origin) das requisições
 * - Prevenir ataques de replay com challenges únicas
 * - Rate limiting agressivo
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.WebAuthService = void 0;
exports.setDatabaseClient = setDatabaseClient;
const drizzle_orm_1 = require("drizzle-orm");
const database_1 = require("@zero/database");
const shared_1 = require("@zero/shared");
const constants_1 = require("../constants");
let dbClient = null;
function setDatabaseClient(client) {
    dbClient = client;
}
function getDB() {
    if (!dbClient) {
        throw new Error('Database client não inicializado');
    }
    return dbClient;
}
exports.WebAuthService = {
    /**
     * NOT PRODUCTION READY
     *
     * Inicia registro de nova credencial WebAuthn
     * Retorna options para navigator.credentials.create()
     */
    async startRegistration(userId, deviceName) {
        // TODO: Implementar com @simplewebauthn/server
        // Por enquanto, retornar erro indicando que feature não está completa
        console.warn('WebAuthn registration not fully implemented yet');
        return {
            success: false,
            error: {
                code: 'FEATURE_NOT_READY',
                message: 'Suporte a WebAuthn/Passkeys será implementado em breve',
            },
        };
    },
    /**
     * NOT PRODUCTION READY
     *
     * Completa registro de credencial WebAuthn
     * Valida response do navegador e armazena credencial
     */
    async completeRegistration(userId, credentialResponse, ipAddress, userAgent) {
        // TODO: Implementar validação completa
        return {
            success: false,
            error: {
                code: 'FEATURE_NOT_READY',
                message: 'Suporte a WebAuthn/Passkeys será implementado em breve',
            },
        };
    },
    /**
     * NOT PRODUCTION READY
     *
     * Inicia autenticação com WebAuthn
     * Retorna options para navigator.credentials.get()
     */
    async startAuthentication() {
        return {
            success: false,
            error: {
                code: 'FEATURE_NOT_READY',
                message: 'Suporte a WebAuthn/Passkeys será implementado em breve',
            },
        };
    },
    /**
     * NOT PRODUCTION READY
     *
     * Completa autenticação WebAuthn
     * Valida assertion response e cria sessão se válido
     */
    async completeAuthentication(credentialResponse, ipAddress, userAgent) {
        return {
            success: false,
            error: {
                code: 'FEATURE_NOT_READY',
                message: 'Suporte a WebAuthn/Passkeys será implementado em breve',
            },
        };
    },
    /**
     * Lista credenciais WebAuthn registradas pelo usuário
     */
    async listCredentials(userId) {
        const db = getDB();
        try {
            const credentials = await db
                .select({
                id: database_1.schema.webauthnCredentials.id,
                credentialType: database_1.schema.webauthnCredentials.credentialType,
                createdAt: database_1.schema.webauthnCredentials.createdAt,
            })
                .from(database_1.schema.webauthnCredentials)
                .where((0, drizzle_orm_1.eq)(database_1.schema.webauthnCredentials.userId, userId));
            return {
                success: true,
                credentials: credentials.map(c => ({
                    id: c.id,
                    type: c.credentialType,
                    createdAt: c.createdAt,
                })),
            };
        }
        catch (error) {
            console.error('Erro ao listar credenciais WebAuthn:', error);
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    /**
     * Remove credencial WebAuthn
     */
    async removeCredential(credentialId, userId, ipAddress, userAgent) {
        const db = getDB();
        try {
            // Verificar ownership
            const credentials = await db
                .select()
                .from(database_1.schema.webauthnCredentials)
                .where((0, drizzle_orm_1.eq)(database_1.schema.webauthnCredentials.id, credentialId))
                .limit(1);
            if (!credentials || credentials.length === 0) {
                return {
                    success: false,
                    error: { code: 'CREDENTIAL_NOT_FOUND', message: 'Credencial não encontrada' },
                };
            }
            if (credentials[0].userId !== userId) {
                return {
                    success: false,
                    error: { code: 'UNAUTHORIZED', message: 'Não autorizado a remover esta credencial' },
                };
            }
            // Remover credencial
            await db
                .delete(database_1.schema.webauthnCredentials)
                .where((0, drizzle_orm_1.eq)(database_1.schema.webauthnCredentials.id, credentialId));
            // Auditoria
            await this.auditLog({
                action: 'WEBAUTHN_AUTHENTICATED', // TODO: criar ação específica para remoção
                userId,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: true,
                metadata: { credentialId, action: 'removed' },
            });
            return { success: true };
        }
        catch (error) {
            console.error('Erro ao remover credencial WebAuthn:', error);
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    async auditLog(event) {
        const db = getDB();
        try {
            await db.insert(database_1.schema.auditLogs).values({
                id: (0, shared_1.generateUUID)(),
                action: event.action,
                userId: event.userId || null,
                sessionId: event.sessionId || null,
                deviceId: event.deviceId || null,
                timestamp: event.timestamp,
                ipAddress: event.ipAddress,
                userAgent: event.userAgent,
                success: event.success,
                failureReason: event.failureReason || null,
                metadata: event.metadata ? JSON.stringify(event.metadata) : null,
            });
        }
        catch (error) {
            console.error('Erro ao criar log de auditoria:', error);
        }
    },
};
//# sourceMappingURL=webauthn.service.js.map
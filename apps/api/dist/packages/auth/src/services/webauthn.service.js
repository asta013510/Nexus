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
import { eq } from 'drizzle-orm';
import { schema } from '@zero/database';
import { generateUUID } from '@zero/shared';
import { AUTH_CONSTANTS } from '../constants';
let dbClient = null;
export function setDatabaseClient(client) {
    dbClient = client;
}
function getDB() {
    if (!dbClient) {
        throw new Error('Database client não inicializado');
    }
    return dbClient;
}
export const WebAuthService = {
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
                id: schema.webauthnCredentials.id,
                credentialType: schema.webauthnCredentials.credentialType,
                createdAt: schema.webauthnCredentials.createdAt,
            })
                .from(schema.webauthnCredentials)
                .where(eq(schema.webauthnCredentials.userId, userId));
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
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
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
                .from(schema.webauthnCredentials)
                .where(eq(schema.webauthnCredentials.id, credentialId))
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
                .delete(schema.webauthnCredentials)
                .where(eq(schema.webauthnCredentials.id, credentialId));
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
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    async auditLog(event) {
        const db = getDB();
        try {
            await db.insert(schema.auditLogs).values({
                id: generateUUID(),
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2ViYXV0aG4uc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uLy4uLy4uLy4uL3BhY2thZ2VzL2F1dGgvc3JjL3NlcnZpY2VzL3dlYmF1dGhuLnNlcnZpY2UudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7Ozs7Ozs7Ozs7Ozs7Ozs7R0FnQkc7QUFFSCxPQUFPLEVBQUUsRUFBRSxFQUFFLE1BQU0sYUFBYSxDQUFDO0FBQ2pDLE9BQU8sRUFBRSxNQUFNLEVBQUUsTUFBTSxnQkFBZ0IsQ0FBQztBQUN4QyxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sY0FBYyxDQUFDO0FBQzVDLE9BQU8sRUFBRSxjQUFjLEVBQUUsTUFBTSxjQUFjLENBQUM7QUFHOUMsSUFBSSxRQUFRLEdBQVEsSUFBSSxDQUFDO0FBRXpCLE1BQU0sVUFBVSxpQkFBaUIsQ0FBQyxNQUFXO0lBQzNDLFFBQVEsR0FBRyxNQUFNLENBQUM7QUFDcEIsQ0FBQztBQUVELFNBQVMsS0FBSztJQUNaLElBQUksQ0FBQyxRQUFRLEVBQUUsQ0FBQztRQUNkLE1BQU0sSUFBSSxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQztJQUN0RCxDQUFDO0lBQ0QsT0FBTyxRQUFRLENBQUM7QUFDbEIsQ0FBQztBQUVELE1BQU0sQ0FBQyxNQUFNLGNBQWMsR0FBRztJQUM1Qjs7Ozs7T0FLRztJQUNILEtBQUssQ0FBQyxpQkFBaUIsQ0FDckIsTUFBYyxFQUNkLFVBQWtCO1FBRWxCLCtDQUErQztRQUMvQyxzRUFBc0U7UUFFdEUsT0FBTyxDQUFDLElBQUksQ0FBQyxpREFBaUQsQ0FBQyxDQUFDO1FBRWhFLE9BQU87WUFDTCxPQUFPLEVBQUUsS0FBSztZQUNkLEtBQUssRUFBRTtnQkFDTCxJQUFJLEVBQUUsbUJBQW1CO2dCQUN6QixPQUFPLEVBQUUsd0RBQXdEO2FBQ2xFO1NBQ0YsQ0FBQztJQUNKLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNILEtBQUssQ0FBQyxvQkFBb0IsQ0FD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QUM7SUFDSCxDQUFDO0lBRUQsS0FBSyxDQUFDLFFBQVEsQ0FBQyxLQUFxQjtRQUNsQyxNQUFNLEVBQUUsR0FBRyxLQUFLLEVBQUUsQ0FBQztRQUVuQixJQUFJLENBQUM7WUFDSCxNQUFNLEVBQUUsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxDQUFDLE1BQU0sQ0FBQztnQkFDdkMsRUFBRSxFQUFFLFlBQVksRUFBRTtnQkFDbEIsTUFBTSxFQUFFLEtBQUssQ0FBQyxNQUFNO2dCQUNwQixNQUFNLEVBQUUsS0FBSyxDQUFDLE1BQU0sSUFBSSxJQUFJO2dCQUM1QixTQUFTLEVBQUUsS0FBSyxDQUFDLFNBQVMsSUFBSSxJQUFJO2dCQUNsQyxRQUFRLEVBQUUsS0FBSyxDQUFDLFFBQVEsSUFBSSxJQUFJO2dCQUNoQyxTQUFTLEVBQUUsS0FBSyxDQUFDLFNBQVM7Z0JBQzFCLFNBQVMsRUFBRSxLQUFLLENBQUMsU0FBUztnQkFDMUIsU0FBUyxFQUFFLEtBQUssQ0FBQyxTQUFTO2dCQUMxQixPQUFPLEVBQUUsS0FBSyxDQUFDLE9BQU87Z0JBQ3RCLGFBQWEsRUFBRSxLQUFLLENBQUMsYUFBYSxJQUFJLElBQUk7Z0JBQzFDLFFBQVEsRUFBRSxLQUFLLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLEtBQUssQ0FBQyxRQUFRLENBQUMsQ0FBQyxDQUFDLENBQUMsSUFBSTthQUNqRSxDQUFDLENBQUM7UUFDTCxDQUFDO1FBQUMsT0FBTyxLQUFLLEVBQUUsQ0FBQztZQUNmLE9BQU8sQ0FBQyxLQUFLLENBQUMsaUNBQWlDLEVBQUUsS0FBSyxDQUFDLENBQUM7UUFDMUQsQ0FBQztJQUNILENBQUM7Q0FDRixDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBTZXJ2acOnbyBXZWJBdXRobi9QYXNza2V5cyAoUGxhY2Vob2xkZXIpXG4gKiBcbiAqIE5PVEE6IEVzdGEgw6kgdW1hIGltcGxlbWVudGHDp8OjbyBpbmljaWFsL3BsYW5uaW5nLlxuICogV2ViQXV0aG4gY29tcGxldG8gcmVxdWVyOlxuICogLSBJbnRlZ3Jhw6fDo28gY29tIEBzaW1wbGV3ZWJhdXRobi9zZXJ2ZXJcbiAqIC0gR2VyYcOnw6NvIGRlIGNoYWxsZW5nZXMgY3JpcHRvZ3LDoWZpY2FzXG4gKiAtIFZhbGlkYcOnw6NvIGRlIGF0dGVzdGF0aW9uL2Fzc2VydGlvbiByZXNwb25zZXNcbiAqIC0gQXJtYXplbmFtZW50byBzZWd1cm8gZGUgY3JlZGVudGlhbCBJRHMgZSBwdWJsaWMga2V5c1xuICogXG4gKiBTRUNVUklUWSBOT1RFUzpcbiAqIC0gVXNhciBhcGVuYXMgY29tbyBmYXRvciBBRElDSU9OQUwsIG51bmNhIMO6bmljb1xuICogLSBSZXF1ZXJlciBNRkEgVE9UUCBjb21vIGZhbGxiYWNrXG4gKiAtIFZhbGlkYXIgb3JpZ2VtIChvcmlnaW4pIGRhcyByZXF1aXNpw6fDtWVzXG4gKiAtIFByZXZlbmlyIGF0YXF1ZXMgZGUgcmVwbGF5IGNvbSBjaGFsbGVuZ2VzIMO6bmljYXNcbiAqIC0gUmF0ZSBsaW1pdGluZyBhZ3Jlc3Npdm9cbiAqL1xuXG5pbXBvcnQgeyBlcSB9IGZyb20gJ2RyaXp6bGUtb3JtJztcbmltcG9ydCB7IHNjaGVtYSB9IGZyb20gJ0B6ZXJvL2RhdGFiYXNlJztcbmltcG9ydCB7IGdlbmVyYXRlVVVJRCB9IGZyb20gJ0B6ZXJvL3NoYXJlZCc7XG5pbXBvcnQgeyBBVVRIX0NPTlNUQU5UUyB9IGZyb20gJy4uL2NvbnN0YW50cyc7XG5pbXBvcnQgdHlwZSB7IEF1dGhBdWRpdEV2ZW50IH0gZnJvbSAnLi4vdHlwZXMnO1xuXG5sZXQgZGJDbGllbnQ6IGFueSA9IG51bGw7XG5cbmV4cG9ydCBmdW5jdGlvbiBzZXREYXRhYmFzZUNsaWVudChjbGllbnQ6IGFueSk6IHZvaWQge1xuICBkYkNsaWVudCA9IGNsaWVudDtcbn1cblxuZnVuY3Rpb24gZ2V0REIoKSB7XG4gIGlmICghZGJDbGllbnQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ0RhdGFiYXNlIGNsaWVudCBuw6NvIGluaWNpYWxpemFkbycpO1xuICB9XG4gIHJldHVybiBkYkNsaWVudDtcbn1cblxuZXhwb3J0IGNvbnN0IFdlYkF1dGhTZXJ2aWNlID0ge1xuICAvKipcbiAgICogTk9UIFBST0RVQ1RJT04gUkVBRFlcbiAgICogXG4gICAqIEluaWNpYSByZWdpc3RybyBkZSBub3ZhIGNyZWRlbmNpYWwgV2ViQXV0aG5cbiAgICogUmV0b3JuYSBvcHRpb25zIHBhcmEgbmF2aWdhdG9yLmNyZWRlbnRpYWxzLmNyZWF0ZSgpXG4gICAqL1xuICBhc3luYyBzdGFydFJlZ2lzdHJhdGlvbihcbiAgICB1c2VySWQ6IHN0cmluZyxcbiAgICBkZXZpY2VOYW1lOiBzdHJpbmdcbiAgKTogUHJvbWlzZTx7IHN1Y2Nlc3M6IGJvb2xlYW47IGNoYWxsZW5nZT86IHN0cmluZzsgcHVibGljS2V5T3B0aW9ucz86IGFueTsgZXJyb3I/OiBhbnkgfT4ge1xuICAgIC8vIFRPRE86IEltcGxlbWVudGFyIGNvbSBAc2ltcGxld2ViYXV0aG4vc2VydmVyXG4gICAgLy8gUG9yIGVucXVhbnRvLCByZXRvcm5hciBlcnJvIGluZGljYW5kbyBxdWUgZmVhdHVyZSBuw6NvIGVzdMOhIGNvbXBsZXRhXG4gICAgXG4gICAgY29uc29sZS53YXJuKCdXZWJBdXRobiByZWdpc3RyYXRpb24gbm90IGZ1bGx5IGltcGxlbWVudGVkIHlldCcpO1xuICAgIFxuICAgIHJldHVybiB7XG4gICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgIGVycm9yOiB7XG4gICAgICAgIGNvZGU6ICdGRUFUVVJFX05PVF9SRUFEWScsXG4gICAgICAgIG1lc3NhZ2U6ICdTdXBvcnRlIGEgV2ViQXV0aG4vUGFzc2tleXMgc2Vyw6EgaW1wbGVtZW50YWRvIGVtIGJyZXZlJyxcbiAgICAgIH0sXG4gICAgfTtcbiAgfSxcblxuICAvKipcbiAgICogTk9UIFBST0RVQ1RJT04gUkVBRFlcbiAgICogXG4gICAqIENvbXBsZXRhIHJlZ2lzdHJvIGRlIGNyZWRlbmNpYWwgV2ViQXV0aG5cbiAgICogVmFsaWRhIHJlc3BvbnNlIGRvIG5hdmVnYWRvciBlIGFybWF6ZW5hIGNyZWRlbmNpYWxcbiAgICovXG4gIGFzeW5jIGNvbXBsZXRlUmVnaXN0cmF0aW9uKFxuICAgIHVzZXJJZDogc3RyaW5nLFxuICAgIGNyZWRlbnRpYWxSZXNwb25zZTogYW55LFxuICAgIGlwQWRkcmVzczogc3RyaW5nLFxuICAgIHVzZXJBZ2VudDogc3RyaW5nXG4gICk6IFByb21pc2U8eyBzdWNjZXNzOiBib29sZWFuOyBlcnJvcj86IGFueSB9PiB7XG4gICAgLy8gVE9ETzogSW1wbGVtZW50YXIgdmFsaWRhw6fDo28gY29tcGxldGFcbiAgICByZXR1cm4ge1xuICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICBlcnJvcjoge1xuICAgICAgICBjb2RlOiAnRkVBVFVSRV9OT1RfUkVBRFknLFxuICAgICAgICBtZXNzYWdlOiAnU3Vwb3J0ZSBhIFdlYkF1dGhuL1Bhc3NrZXlzIHNlcsOhIGltcGxlbWVudGFkbyBlbSBicmV2ZScsXG4gICAgICB9LFxuICAgIH07XG4gIH0sXG5cbiAgLyoqXG4gICAqIE5PVCBQUk9EVUNUSU9OIFJFQURZXG4gICAqIFxuICAgKiBJbmljaWEgYXV0ZW50aWNhw6fDo28gY29tIFdlYkF1dGhuXG4gICAqIFJldG9ybmEgb3B0aW9ucyBwYXJhIG5hdmlnYXRvci5jcmVkZW50aWFscy5nZXQoKVxuICAgKi9cbiAgYXN5bmMgc3RhcnRBdXRoZW50aWNhdGlvbigpOiBQcm9taXNlPHsgc3VjY2VzczogYm9vbGVhbjsgY2hhbGxlbmdlPzogc3RyaW5nOyBwdWJsaWNLZXlPcHRpb25zPzogYW55OyBlcnJvcj86IGFueSB9PiB7XG4gICAgcmV0dXJuIHtcbiAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgZXJyb3I6IHtcbiAgICAgICAgY29kZTogJ0ZFQVRVUkVfTk9UX1JFQURZJyxcbiAgICAgICAgbWVzc2FnZTogJ1N1cG9ydGUgYSBXZWJBdXRobi9QYXNza2V5cyBzZXLDoSBpbXBsZW1lbnRhZG8gZW0gYnJldmUnLFxuICAgICAgfSxcbiAgICB9O1xuICB9LFxuXG4gIC8qKlxuICAgKiBOT1QgUFJPRFVDVElPTiBSRUFEWVxuICAgKiBcbiAgICogQ29tcGxldGEgYXV0ZW50aWNhw6fDo28gV2ViQXV0aG5cbiAgICogVmFsaWRhIGFzc2VydGlvbiByZXNwb25zZSBlIGNyaWEgc2Vzc8OjbyBzZSB2w6FsaWRvXG4gICAqL1xuICBhc3luYyBjb21wbGV0ZUF1dGhlbnRpY2F0aW9uKFxuICAgIGNyZWRlbnRpYWxSZXNwb25zZTogYW55LFxuICAgIGlwQWRkcmVzczogc3RyaW5nLFxuICAgIHVzZXJBZ2VudDogc3RyaW5nXG4gICk6IFByb21pc2U8eyBzdWNjZXNzOiBib29sZWFuOyBzZXNzaW9uPzogYW55OyBlcnJvcj86IGFueSB9PiB7XG4gICAgcmV0dXJuIHtcbiAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgZXJyb3I6IHtcbiAgICAgICAgY29kZTogJ0ZFQVRVUkVfTk9UX1JFQURZJyxcbiAgICAgICAgbWVzc2FnZTogJ1N1cG9ydGUgYSBXZWJBdXRobi9QYXNza2V5cyBzZXLDoSBpbXBsZW1lbnRhZG8gZW0gYnJldmUnLFxuICAgICAgfSxcbiAgICB9O1xuICB9LFxuXG4gIC8qKlxuICAgKiBMaXN0YSBjcmVkZW5jaWFpcyBXZWJBdXRobiByZWdpc3RyYWRhcyBwZWxvIHVzdcOhcmlvXG4gICAqL1xuICBhc3luYyBsaXN0Q3JlZGVudGlhbHModXNlcklkOiBzdHJpbmcpOiBQcm9taXNlPHsgc3VjY2VzczogYm9vbGVhbjsgY3JlZGVudGlhbHM/OiBhbnlbXTsgZXJyb3I/OiBhbnkgfT4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcblxuICAgIHRyeSB7XG4gICAgICBjb25zdCBjcmVkZW50aWFscyA9IGF3YWl0IGRiXG4gICAgICAgIC5zZWxlY3Qoe1xuICAgICAgICAgIGlkOiBzY2hlbWEud2ViYXV0aG5DcmVkZW50aWFscy5pZCxcbiAgICAgICAgICBjcmVkZW50aWFsVHlwZTogc2NoZW1hLndlYmF1dGhuQ3JlZGVudGlhbHMuY3JlZGVudGlhbFR5cGUsXG4gICAgICAgICAgY3JlYXRlZEF0OiBzY2hlbWEud2ViYXV0aG5DcmVkZW50aWFscy5jcmVhdGVkQXQsXG4gICAgICAgIH0pXG4gICAgICAgIC5mcm9tKHNjaGVtYS53ZWJhdXRobkNyZWRlbnRpYWxzKVxuICAgICAgICAud2hlcmUoZXEoc2NoZW1hLndlYmF1dGhuQ3JlZGVudGlhbHMudXNlcklkLCB1c2VySWQpKTtcblxuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgY3JlZGVudGlhbHM6IGNyZWRlbnRpYWxzLm1hcChjID0+ICh7XG4gICAgICAgICAgaWQ6IGMuaWQsXG4gICAgICAgICAgdHlwZTogYy5jcmVkZW50aWFsVHlwZSxcbiAgICAgICAgICBjcmVhdGVkQXQ6IGMuY3JlYXRlZEF0LFxuICAgICAgICB9KSksXG4gICAgICB9O1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdFcnJvIGFvIGxpc3RhciBjcmVkZW5jaWFpcyBXZWJBdXRobjonLCBlcnJvcik7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZXJyb3I6IHsgY29kZTogJ0lOVEVSTkFMX0VSUk9SJywgbWVzc2FnZTogQVVUSF9DT05TVEFOVFMuRVJST1JfTUVTU0FHRVMuSU5URVJOQUxfRVJST1IgfSxcbiAgICAgIH07XG4gICAgfVxuICB9LFxuXG4gIC8qKlxuICAgKiBSZW1vdmUgY3JlZGVuY2lhbCBXZWJBdXRoblxuICAgKi9cbiAgYXN5bmMgcmVtb3ZlQ3JlZGVudGlhbChcbiAgICBjcmVkZW50aWFsSWQ6IHN0cmluZyxcbiAgICB1c2VySWQ6IHN0cmluZyxcbiAgICBpcEFkZHJlc3M6IHN0cmluZyxcbiAgICB1c2VyQWdlbnQ6IHN0cmluZ1xuICApOiBQcm9taXNlPHsgc3VjY2VzczogYm9vbGVhbjsgZXJyb3I/OiBhbnkgfT4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcblxuICAgIHRyeSB7XG4gICAgICAvLyBWZXJpZmljYXIgb3duZXJzaGlwXG4gICAgICBjb25zdCBjcmVkZW50aWFscyA9IGF3YWl0IGRiXG4gICAgICAgIC5zZWxlY3QoKVxuICAgICAgICAuZnJvbShzY2hlbWEud2ViYXV0aG5DcmVkZW50aWFscylcbiAgICAgICAgLndoZXJlKFxuICAgICAgICAgIGVxKHNjaGVtYS53ZWJhdXRobkNyZWRlbnRpYWxzLmlkLCBjcmVkZW50aWFsSWQpXG4gICAgICAgIClcbiAgICAgICAgLmxpbWl0KDEpO1xuXG4gICAgICBpZiAoIWNyZWRlbnRpYWxzIHx8IGNyZWRlbnRpYWxzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgIGVycm9yOiB7IGNvZGU6ICdDUkVERU5USUFMX05PVF9GT1VORCcsIG1lc3NhZ2U6ICdDcmVkZW5jaWFsIG7Do28gZW5jb250cmFkYScgfSxcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgaWYgKGNyZWRlbnRpYWxzWzBdLnVzZXJJZCAhPT0gdXNlcklkKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgZXJyb3I6IHsgY29kZTogJ1VOQVVUSE9SSVpFRCcsIG1lc3NhZ2U6ICdOw6NvIGF1dG9yaXphZG8gYSByZW1vdmVyIGVzdGEgY3JlZGVuY2lhbCcgfSxcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgLy8gUmVtb3ZlciBjcmVkZW5jaWFsXG4gICAgICBhd2FpdCBkYlxuICAgICAgICAuZGVsZXRlKHNjaGVtYS53ZWJhdXRobkNyZWRlbnRpYWxzKVxuICAgICAgICAud2hlcmUoZXEoc2NoZW1hLndlYmF1dGhuQ3JlZGVudGlhbHMuaWQsIGNyZWRlbnRpYWxJZCkpO1xuXG4gICAgICAvLyBBdWRpdG9yaWFcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdXRUJBVVRITl9BVVRIRU5USUNBVEVEJywgLy8gVE9ETzogY3JpYXIgYcOnw6NvIGVzcGVjw61maWNhIHBhcmEgcmVtb8Onw6NvXG4gICAgICAgIHVzZXJJZCxcbiAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgbWV0YWRhdGE6IHsgY3JlZGVudGlhbElkLCBhY3Rpb246ICdyZW1vdmVkJyB9LFxuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IHRydWUgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgY29uc29sZS5lcnJvcignRXJybyBhbyByZW1vdmVyIGNyZWRlbmNpYWwgV2ViQXV0aG46JywgZXJyb3IpO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlRFUk5BTF9FUlJPUicsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLklOVEVSTkFMX0VSUk9SIH0sXG4gICAgICB9O1xuICAgIH1cbiAgfSxcblxuICBhc3luYyBhdWRpdExvZyhldmVudDogQXV0aEF1ZGl0RXZlbnQpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG4gICAgXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IGRiLmluc2VydChzY2hlbWEuYXVkaXRMb2dzKS52YWx1ZXMoe1xuICAgICAgICBpZDogZ2VuZXJhdGVVVUlEKCksXG4gICAgICAgIGFjdGlvbjogZXZlbnQuYWN0aW9uLFxuICAgICAgICB1c2VySWQ6IGV2ZW50LnVzZXJJZCB8fCBudWxsLFxuICAgICAgICBzZXNzaW9uSWQ6IGV2ZW50LnNlc3Npb25JZCB8fCBudWxsLFxuICAgICAgICBkZXZpY2VJZDogZXZlbnQuZGV2aWNlSWQgfHwgbnVsbCxcbiAgICAgICAgdGltZXN0YW1wOiBldmVudC50aW1lc3RhbXAsXG4gICAgICAgIGlwQWRkcmVzczogZXZlbnQuaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQ6IGV2ZW50LnVzZXJBZ2VudCxcbiAgICAgICAgc3VjY2VzczogZXZlbnQuc3VjY2VzcyxcbiAgICAgICAgZmFpbHVyZVJlYXNvbjogZXZlbnQuZmFpbHVyZVJlYXNvbiB8fCBudWxsLFxuICAgICAgICBtZXRhZGF0YTogZXZlbnQubWV0YWRhdGEgPyBKU09OLnN0cmluZ2lmeShldmVudC5tZXRhZGF0YSkgOiBudWxsLFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm8gYW8gY3JpYXIgbG9nIGRlIGF1ZGl0b3JpYTonLCBlcnJvcik7XG4gICAgfVxuICB9LFxufTtcbiJdfQ==
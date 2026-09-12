/**
 * Serviço de MFA (Multi-Factor Authentication)
 *
 * Responsabilidades:
 * - Setup de TOTP para usuários
 * - Verificação de códigos TOTP
 * - Gerenciamento de backup codes
 * - Auditoria de eventos MFA
 *
 * SECURITY NOTES:
 * - TOTP baseado em RFC 6238
 * - Backup codes hasheados antes de armazenar
 * - Rate limiting em verificações
 * - Janela de tempo limitada para códigos
 */
import { eq } from 'drizzle-orm';
import { sha256, generateTOTPSecret, verifyTOTP, generateRecoveryCodes } from '@zero/crypto';
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
export const MFAService = {
    /**
     * Inicia setup de MFA para usuário
     * Retorna secret TOTP e QR code URI
     */
    async initiateMFASetup(userId, emailAddress) {
        const db = getDB();
        try {
            // Verificar se usuário já tem MFA habilitado
            const users = await db
                .select({ mfaEnabled: schema.users.mfaEnabled })
                .from(schema.users)
                .where(eq(schema.users.id, userId))
                .limit(1);
            if (!users || users.length === 0) {
                return {
                    success: false,
                    error: { code: 'USER_NOT_FOUND', message: 'Usuário não encontrado' },
                };
            }
            if (users[0].mfaEnabled) {
                return {
                    success: false,
                    error: { code: 'MFA_ALREADY_ENABLED', message: 'MFA já está habilitado' },
                };
            }
            // Gerar secret TOTP
            const totpSecret = generateTOTPSecret();
            // Criar URI para QR Code (padrão Google Authenticator)
            const issuer = encodeURIComponent('ZERO Security');
            const label = encodeURIComponent(emailAddress);
            const secret = totpSecret.secret;
            const algorithm = encodeURIComponent('SHA1');
            const digits = 6;
            const period = 30;
            const otpauthURI = `otpauth://totp/${issuer}:${label}?secret=${secret}&issuer=${issuer}&algorithm=${algorithm}&digits=${digits}&period=${period}`;
            // Armazenar secret temporariamente (será confirmada após verificação)
            // Em produção, usar Redis com TTL de 15 minutos
            await db.insert(schema.webauthnCredentials).values({
                id: generateUUID(),
                userId,
                credentialId: Buffer.from(`totp_temp_${userId}`).toString('base64url'),
                credentialType: 'totp_setup',
                publicKey: secret, // Armazena secret temporariamente
                counter: 0,
                createdAt: new Date(),
                // Usar campo auxiliar para metadata temporária
            });
            return {
                success: true,
                totpSecret: secret,
                otpauthURI,
                requiresVerification: true,
            };
        }
        catch (error) {
            console.error('Erro ao iniciar setup MFA:', error);
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    /**
     * Verifica código TOTP durante setup
     * Se válido, habilita MFA permanentemente e gera recovery codes
     */
    async verifyMFASetup(userId, totpCode, ipAddress, userAgent) {
        const db = getDB();
        try {
            // Buscar secret temporária
            const credentials = await db
                .select()
                .from(schema.webauthnCredentials)
                .where(eq(schema.webauthnCredentials.credentialId, Buffer.from(`totp_temp_${userId}`).toString('base64url')))
                .limit(1);
            if (!credentials || credentials.length === 0) {
                return {
                    success: false,
                    error: { code: 'MFA_SETUP_NOT_INITIATED', message: 'Setup de MFA não iniciado' },
                };
            }
            const secret = credentials[0].publicKey;
            // Verificar código TOTP
            const isValid = verifyTOTP(totpCode, secret);
            if (!isValid) {
                return {
                    success: false,
                    error: { code: 'INVALID_TOTP_CODE', message: 'Código TOTP inválido' },
                };
            }
            // MFA verificado com sucesso
            // Remover credential temporária
            await db
                .delete(schema.webauthnCredentials)
                .where(eq(schema.webauthnCredentials.credentialId, Buffer.from(`totp_temp_${userId}`).toString('base64url')));
            // Habilitar MFA no usuário
            await db
                .update(schema.users)
                .set({
                mfaEnabled: true,
                status: 'active',
                updatedAt: new Date(),
            })
                .where(eq(schema.users.id, userId));
            // Gerar recovery codes
            const recoveryCodes = generateRecoveryCodes(AUTH_CONSTANTS.RECOVERY_CODE_COUNT);
            // Salvar recovery codes hasheados
            for (const code of recoveryCodes) {
                const hashedCode = await sha256(code);
                const codePrefix = code.substring(0, 4); // Primeiros 4 caracteres para identificação
                const newRecoveryCode = {
                    id: generateUUID(),
                    userId,
                    codeHash: hashedCode,
                    codePrefix,
                    usedAt: null,
                    createdAt: new Date(),
                };
                await db.insert(schema.recoveryCodes).values(newRecoveryCode);
            }
            // Auditoria
            await this.auditLog({
                action: 'MFA_ENABLED',
                userId,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: true,
            });
            return {
                success: true,
                recoveryCodes,
            };
        }
        catch (error) {
            console.error('Erro ao verificar setup MFA:', error);
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    /**
     * Verifica código TOTP durante login
     */
    async verifyTOTP(userId, totpCode) {
        const db = getDB();
        try {
            // Buscar usuário para obter secret
            const users = await db
                .select()
                .from(schema.users)
                .where(eq(schema.users.id, userId))
                .limit(1);
            if (!users || users.length === 0) {
                return {
                    success: false,
                    error: { code: 'USER_NOT_FOUND', message: 'Usuário não encontrado' },
                };
            }
            const user = users[0];
            if (!user.mfaEnabled) {
                return {
                    success: false,
                    error: { code: 'MFA_NOT_ENABLED', message: 'MFA não habilitado' },
                };
            }
            // Buscar credenciais WebAuthn (que armazenam o secret TOTP)
            const credentials = await db
                .select()
                .from(schema.webauthnCredentials)
                .where(eq(schema.webauthnCredentials.userId, userId))
                .limit(1);
            if (!credentials || credentials.length === 0) {
                return {
                    success: false,
                    error: { code: 'MFA_CREDENTIAL_NOT_FOUND', message: 'Credencial MFA não encontrada' },
                };
            }
            const secret = credentials[0].publicKey;
            // Verificar código
            const isValid = verifyTOTP(totpCode, secret);
            if (!isValid) {
                return {
                    success: false,
                    error: { code: 'INVALID_TOTP_CODE', message: 'Código TOTP inválido' },
                };
            }
            return { success: true };
        }
        catch (error) {
            console.error('Erro ao verificar TOTP:', error);
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    /**
     * Usa recovery code para autenticar
     */
    async useRecoveryCode(userId, recoveryCode, ipAddress, userAgent) {
        const db = getDB();
        try {
            const hashedCode = await sha256(recoveryCode);
            // Buscar recovery code
            const codes = await db
                .select()
                .from(schema.recoveryCodes)
                .where(eq(schema.recoveryCodes.codeHash, hashedCode))
                .limit(1);
            if (!codes || codes.length === 0) {
                return {
                    success: false,
                    error: { code: 'INVALID_RECOVERY_CODE', message: 'Recovery code inválido' },
                };
            }
            const code = codes[0];
            // Verificar se já foi usado
            if (code.usedAt !== null) {
                return {
                    success: false,
                    error: { code: 'RECOVERY_CODE_USED', message: 'Recovery code já utilizado' },
                };
            }
            // Verificar se pertence ao usuário
            if (code.userId !== userId) {
                return {
                    success: false,
                    error: { code: 'INVALID_RECOVERY_CODE', message: 'Recovery code inválido' },
                };
            }
            // Marcar como usado
            await db
                .update(schema.recoveryCodes)
                .set({
                usedAt: new Date(),
            })
                .where(eq(schema.recoveryCodes.id, code.id));
            // Auditoria
            await this.auditLog({
                action: 'RECOVERY_CODE_USED',
                userId,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: true,
                metadata: { codeId: code.id },
            });
            return { success: true };
        }
        catch (error) {
            console.error('Erro ao usar recovery code:', error);
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    /**
     * Gera novos recovery codes (requer autenticação prévia)
     */
    async regenerateRecoveryCodes(userId, ipAddress, userAgent) {
        const db = getDB();
        try {
            // Invalidar todos os recovery codes existentes
            await db
                .update(schema.recoveryCodes)
                .set({
                usedAt: new Date(), // Marcar todos como "usados" para invalidar
            })
                .where(eq(schema.recoveryCodes.userId, userId));
            // Gerar novos codes
            const recoveryCodes = generateRecoveryCodes(AUTH_CONSTANTS.RECOVERY_CODE_COUNT);
            // Salvar novos codes hasheados
            for (const code of recoveryCodes) {
                const hashedCode = await sha256(code);
                const codePrefix = code.substring(0, 4); // Primeiros 4 caracteres para identificação
                const newRecoveryCode = {
                    id: generateUUID(),
                    userId,
                    codeHash: hashedCode,
                    codePrefix,
                    usedAt: null,
                    createdAt: new Date(),
                };
                await db.insert(schema.recoveryCodes).values(newRecoveryCode);
            }
            // Auditoria
            await this.auditLog({
                action: 'RECOVERY_CODES_REGENERATED',
                userId,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: true,
            });
            return {
                success: true,
                recoveryCodes,
            };
        }
        catch (error) {
            console.error('Erro ao regenerar recovery codes:', error);
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    /**
     * Desabilita MFA do usuário (operação de alto risco)
     */
    async disableMFA(userId, password, ipAddress, userAgent) {
        const db = getDB();
        try {
            const users = await db
                .select({ passwordHash: schema.users.passwordHash })
                .from(schema.users)
                .where(eq(schema.users.id, userId))
                .limit(1);
            if (!users || users.length === 0) {
                return {
                    success: false,
                    error: { code: 'USER_NOT_FOUND', message: 'Usuário não encontrado' },
                };
            }
            // TODO: Verificar senha aqui (importar argon2idVerify)
            // Por enquanto, apenas desabilita MFA
            await db
                .update(schema.users)
                .set({
                mfaEnabled: false,
                status: 'pending_mfa',
                updatedAt: new Date(),
            })
                .where(eq(schema.users.id, userId));
            // Remover credenciais TOTP
            await db
                .delete(schema.webauthnCredentials)
                .where(eq(schema.webauthnCredentials.userId, userId));
            // Invalidar recovery codes
            await db
                .update(schema.recoveryCodes)
                .set({
                usedAt: new Date(),
            })
                .where(eq(schema.recoveryCodes.userId, userId));
            // Auditoria
            await this.auditLog({
                action: 'MFA_DISABLED',
                userId,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: true,
            });
            return { success: true };
        }
        catch (error) {
            console.error('Erro ao desabilitar MFA:', error);
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWZhLnNlcnZpY2UuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi8uLi8uLi8uLi9wYWNrYWdlcy9hdXRoL3NyYy9zZXJ2aWNlcy9tZmEuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7Ozs7Ozs7Ozs7R0FjRztBQUVILE9BQU8sRUFBRSxFQUFFLEVBQUUsTUFBTSxhQUFhLENBQUM7QUFDakMsT0FBTyxFQUFFLE1BQU0sRUFBRSxrQkFBa0IsRUFBRSxVQUFVLEVBQUUscUJBQXFCLEVBQUUsTUFBTSxjQUFjLENBQUM7QUFDN0YsT0FBTyxFQUFFLE1BQU0sRUFBd0IsTUFBTSxnQkFBZ0IsQ0FBQztBQUM5RCxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sY0FBYyxDQUFDO0FBQzVDLE9BQU8sRUFBRSxjQUFjLEVBQUUsTUFBTSxjQUFjLENBQUM7QUFHOUMsSUFBSSxRQUFRLEdBQVEsSUFBSSxDQUFDO0FBRXpCLE1BQU0sVUFBVSxpQkFBaUIsQ0FBQyxNQUFXO0lBQzNDLFFBQVEsR0FBRyxNQUFNLENBQUM7QUFDcEIsQ0FBQztBQUVELFNBQVMsS0FBSztJQUNaLElBQUksQ0FBQyxRQUFRLEVBQUUsQ0FBQztRQUNkLE1BQU0sSUFBSSxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQztJQUN0RCxDQUFDO0lBQ0QsT0FBTyxRQUFRLENBQUM7QUFDbEIsQ0FBQztBQUVELE1BQU0sQ0FBQyxNQUFNLFVBQVUsR0FBRztJQUN4Qjs7O09BR0c7SUFDSCxLQUFLLENBQUMsZ0JBQWdCLENBQ3BCLE1BQWMsRUFDZCxZQUFvQjtRQUVwQixNQUFNLEVBQUUsR0FBRyxLQUFLLEVBQUUsQ0FBQztRQUVuQixJQUFJLENBQUM7WUFDSCw2Q0FBNkM7WUFDN0MsTUFBTSxLQUFLLEdBQUcsTUFBTSxFQUFFO2lCQUNuQixNQUFNLENBQUMsRUFBRSxVQUFVLEVBQUUsTUFBTSxDQUFDLEtBQUssQ0FBQyxVQUFVLEVBQUUsQ0FBQztpQkFD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RkEgKE11bHRpLUZhY3RvciBBdXRoZW50aWNhdGlvbilcbiAqIFxuICogUmVzcG9uc2FiaWxpZGFkZXM6XG4gKiAtIFNldHVwIGRlIFRPVFAgcGFyYSB1c3XDoXJpb3NcbiAqIC0gVmVyaWZpY2HDp8OjbyBkZSBjw7NkaWdvcyBUT1RQXG4gKiAtIEdlcmVuY2lhbWVudG8gZGUgYmFja3VwIGNvZGVzXG4gKiAtIEF1ZGl0b3JpYSBkZSBldmVudG9zIE1GQVxuICogXG4gKiBTRUNVUklUWSBOT1RFUzpcbiAqIC0gVE9UUCBiYXNlYWRvIGVtIFJGQyA2MjM4XG4gKiAtIEJhY2t1cCBjb2RlcyBoYXNoZWFkb3MgYW50ZXMgZGUgYXJtYXplbmFyXG4gKiAtIFJhdGUgbGltaXRpbmcgZW0gdmVyaWZpY2HDp8O1ZXNcbiAqIC0gSmFuZWxhIGRlIHRlbXBvIGxpbWl0YWRhIHBhcmEgY8OzZGlnb3NcbiAqL1xuXG5pbXBvcnQgeyBlcSB9IGZyb20gJ2RyaXp6bGUtb3JtJztcbmltcG9ydCB7IHNoYTI1NiwgZ2VuZXJhdGVUT1RQU2VjcmV0LCB2ZXJpZnlUT1RQLCBnZW5lcmF0ZVJlY292ZXJ5Q29kZXMgfSBmcm9tICdAemVyby9jcnlwdG8nO1xuaW1wb3J0IHsgc2NoZW1hLCB0eXBlIE5ld1JlY292ZXJ5Q29kZSB9IGZyb20gJ0B6ZXJvL2RhdGFiYXNlJztcbmltcG9ydCB7IGdlbmVyYXRlVVVJRCB9IGZyb20gJ0B6ZXJvL3NoYXJlZCc7XG5pbXBvcnQgeyBBVVRIX0NPTlNUQU5UUyB9IGZyb20gJy4uL2NvbnN0YW50cyc7XG5pbXBvcnQgdHlwZSB7IE1GQVNldHVwUmVzcG9uc2UsIE1GQVZlcmlmeVJlc3BvbnNlLCBBdXRoQXVkaXRFdmVudCB9IGZyb20gJy4uL3R5cGVzJztcblxubGV0IGRiQ2xpZW50OiBhbnkgPSBudWxsO1xuXG5leHBvcnQgZnVuY3Rpb24gc2V0RGF0YWJhc2VDbGllbnQoY2xpZW50OiBhbnkpOiB2b2lkIHtcbiAgZGJDbGllbnQgPSBjbGllbnQ7XG59XG5cbmZ1bmN0aW9uIGdldERCKCkge1xuICBpZiAoIWRiQ2xpZW50KSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdEYXRhYmFzZSBjbGllbnQgbsOjbyBpbmljaWFsaXphZG8nKTtcbiAgfVxuICByZXR1cm4gZGJDbGllbnQ7XG59XG5cbmV4cG9ydCBjb25zdCBNRkFTZXJ2aWNlID0ge1xuICAvKipcbiAgICogSW5pY2lhIHNldHVwIGRlIE1GQSBwYXJhIHVzdcOhcmlvXG4gICAqIFJldG9ybmEgc2VjcmV0IFRPVFAgZSBRUiBjb2RlIFVSSVxuICAgKi9cbiAgYXN5bmMgaW5pdGlhdGVNRkFTZXR1cChcbiAgICB1c2VySWQ6IHN0cmluZyxcbiAgICBlbWFpbEFkZHJlc3M6IHN0cmluZ1xuICApOiBQcm9taXNlPE1GQVNldHVwUmVzcG9uc2U+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG5cbiAgICB0cnkge1xuICAgICAgLy8gVmVyaWZpY2FyIHNlIHVzdcOhcmlvIGrDoSB0ZW0gTUZBIGhhYmlsaXRhZG9cbiAgICAgIGNvbnN0IHVzZXJzID0gYXdhaXQgZGJcbiAgICAgICAgLnNlbGVjdCh7IG1mYUVuYWJsZWQ6IHNjaGVtYS51c2Vycy5tZmFFbmFibGVkIH0pXG4gICAgICAgIC5mcm9tKHNjaGVtYS51c2VycylcbiAgICAgICAgLndoZXJlKGVxKHNjaGVtYS51c2Vycy5pZCwgdXNlcklkKSlcbiAgICAgICAgLmxpbWl0KDEpO1xuXG4gICAgICBpZiAoIXVzZXJzIHx8IHVzZXJzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgIGVycm9yOiB7IGNvZGU6ICdVU0VSX05PVF9GT1VORCcsIG1lc3NhZ2U6ICdVc3XDoXJpbyBuw6NvIGVuY29udHJhZG8nIH0sXG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIGlmICh1c2Vyc1swXS5tZmFFbmFibGVkKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgZXJyb3I6IHsgY29kZTogJ01GQV9BTFJFQURZX0VOQUJMRUQnLCBtZXNzYWdlOiAnTUZBIGrDoSBlc3TDoSBoYWJpbGl0YWRvJyB9LFxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICAvLyBHZXJhciBzZWNyZXQgVE9UUFxuICAgICAgY29uc3QgdG90cFNlY3JldCA9IGdlbmVyYXRlVE9UUFNlY3JldCgpO1xuICAgICAgXG4gICAgICAvLyBDcmlhciBVUkkgcGFyYSBRUiBDb2RlIChwYWRyw6NvIEdvb2dsZSBBdXRoZW50aWNhdG9yKVxuICAgICAgY29uc3QgaXNzdWVyID0gZW5jb2RlVVJJQ29tcG9uZW50KCdaRVJPIFNlY3VyaXR5Jyk7XG4gICAgICBjb25zdCBsYWJlbCA9IGVuY29kZVVSSUNvbXBvbmVudChlbWFpbEFkZHJlc3MpO1xuICAgICAgY29uc3Qgc2VjcmV0ID0gdG90cFNlY3JldC5zZWNyZXQ7XG4gICAgICBjb25zdCBhbGdvcml0aG0gPSBlbmNvZGVVUklDb21wb25lbnQoJ1NIQTEnKTtcbiAgICAgIGNvbnN0IGRpZ2l0cyA9IDY7XG4gICAgICBjb25zdCBwZXJpb2QgPSAzMDtcblxuICAgICAgY29uc3Qgb3RwYXV0aFVSSSA9IGBvdHBhdXRoOi8vdG90cC8ke2lzc3Vlcn06JHtsYWJlbH0/c2VjcmV0PSR7c2VjcmV0fSZpc3N1ZXI9JHtpc3N1ZXJ9JmFsZ29yaXRobT0ke2FsZ29yaXRobX0mZGlnaXRzPSR7ZGlnaXRzfSZwZXJpb2Q9JHtwZXJpb2R9YDtcblxuICAgICAgLy8gQXJtYXplbmFyIHNlY3JldCB0ZW1wb3JhcmlhbWVudGUgKHNlcsOhIGNvbmZpcm1hZGEgYXDDs3MgdmVyaWZpY2HDp8OjbylcbiAgICAgIC8vIEVtIHByb2R1w6fDo28sIHVzYXIgUmVkaXMgY29tIFRUTCBkZSAxNSBtaW51dG9zXG4gICAgICBhd2FpdCBkYi5pbnNlcnQoc2NoZW1hLndlYmF1dGhuQ3JlZGVudGlhbHMpLnZhbHVlcyh7XG4gICAgICAgIGlkOiBnZW5lcmF0ZVVVSUQoKSxcbiAgICAgICAgdXNlcklkLFxuICAgICAgICBjcmVkZW50aWFsSWQ6IEJ1ZmZlci5mcm9tKGB0b3RwX3RlbXBfJHt1c2VySWR9YCkudG9TdHJpbmcoJ2Jhc2U2NHVybCcpLFxuICAgICAgICBjcmVkZW50aWFsVHlwZTogJ3RvdHBfc2V0dXAnLFxuICAgICAgICBwdWJsaWNLZXk6IHNlY3JldCwgLy8gQXJtYXplbmEgc2VjcmV0IHRlbXBvcmFyaWFtZW50ZVxuICAgICAgICBjb3VudGVyOiAwLFxuICAgICAgICBjcmVhdGVkQXQ6IG5ldyBEYXRlKCksXG4gICAgICAgIC8vIFVzYXIgY2FtcG8gYXV4aWxpYXIgcGFyYSBtZXRhZGF0YSB0ZW1wb3LDoXJpYVxuICAgICAgfSBhcyBhbnkpO1xuXG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICB0b3RwU2VjcmV0OiBzZWNyZXQsXG4gICAgICAgIG90cGF1dGhVUkksXG4gICAgICAgIHJlcXVpcmVzVmVyaWZpY2F0aW9uOiB0cnVlLFxuICAgICAgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgY29uc29sZS5lcnJvcignRXJybyBhbyBpbmljaWFyIHNldHVwIE1GQTonLCBlcnJvcik7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZXJyb3I6IHsgY29kZTogJ0lOVEVSTkFMX0VSUk9SJywgbWVzc2FnZTogQVVUSF9DT05TVEFOVFMuRVJST1JfTUVTU0FHRVMuSU5URVJOQUxfRVJST1IgfSxcbiAgICAgIH07XG4gICAgfVxuICB9LFxuXG4gIC8qKlxuICAgKiBWZXJpZmljYSBjw7NkaWdvIFRPVFAgZHVyYW50ZSBzZXR1cFxuICAgKiBTZSB2w6FsaWRvLCBoYWJpbGl0YSBNRkEgcGVybWFuZW50ZW1lbnRlIGUgZ2VyYSByZWNvdmVyeSBjb2Rlc1xuICAgKi9cbiAgYXN5bmMgdmVyaWZ5TUZBU2V0dXAoXG4gICAgdXNlcklkOiBzdHJpbmcsXG4gICAgdG90cENvZGU6IHN0cmluZyxcbiAgICBpcEFkZHJlc3M6IHN0cmluZyxcbiAgICB1c2VyQWdlbnQ6IHN0cmluZ1xuICApOiBQcm9taXNlPHsgc3VjY2VzczogYm9vbGVhbjsgcmVjb3ZlcnlDb2Rlcz86IHN0cmluZ1tdOyBlcnJvcj86IGFueSB9PiB7XG4gICAgY29uc3QgZGIgPSBnZXREQigpO1xuXG4gICAgdHJ5IHtcbiAgICAgIC8vIEJ1c2NhciBzZWNyZXQgdGVtcG9yw6FyaWFcbiAgICAgIGNvbnN0IGNyZWRlbnRpYWxzID0gYXdhaXQgZGJcbiAgICAgICAgLnNlbGVjdCgpXG4gICAgICAgIC5mcm9tKHNjaGVtYS53ZWJhdXRobkNyZWRlbnRpYWxzKVxuICAgICAgICAud2hlcmUoXG4gICAgICAgICAgZXEoc2NoZW1hLndlYmF1dGhuQ3JlZGVudGlhbHMuY3JlZGVudGlhbElkLCBCdWZmZXIuZnJvbShgdG90cF90ZW1wXyR7dXNlcklkfWApLnRvU3RyaW5nKCdiYXNlNjR1cmwnKSlcbiAgICAgICAgKVxuICAgICAgICAubGltaXQoMSk7XG5cbiAgICAgIGlmICghY3JlZGVudGlhbHMgfHwgY3JlZGVudGlhbHMubGVuZ3RoID09PSAwKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgZXJyb3I6IHsgY29kZTogJ01GQV9TRVRVUF9OT1RfSU5JVElBVEVEJywgbWVzc2FnZTogJ1NldHVwIGRlIE1GQSBuw6NvIGluaWNpYWRvJyB9LFxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICBjb25zdCBzZWNyZXQgPSBjcmVkZW50aWFsc1swXS5wdWJsaWNLZXk7XG5cbiAgICAgIC8vIFZlcmlmaWNhciBjw7NkaWdvIFRPVFBcbiAgICAgIGNvbnN0IGlzVmFsaWQgPSB2ZXJpZnlUT1RQKHRvdHBDb2RlLCBzZWNyZXQpO1xuXG4gICAgICBpZiAoIWlzVmFsaWQpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICBlcnJvcjogeyBjb2RlOiAnSU5WQUxJRF9UT1RQX0NPREUnLCBtZXNzYWdlOiAnQ8OzZGlnbyBUT1RQIGludsOhbGlkbycgfSxcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgLy8gTUZBIHZlcmlmaWNhZG8gY29tIHN1Y2Vzc29cbiAgICAgIC8vIFJlbW92ZXIgY3JlZGVudGlhbCB0ZW1wb3LDoXJpYVxuICAgICAgYXdhaXQgZGJcbiAgICAgICAgLmRlbGV0ZShzY2hlbWEud2ViYXV0aG5DcmVkZW50aWFscylcbiAgICAgICAgLndoZXJlKFxuICAgICAgICAgIGVxKHNjaGVtYS53ZWJhdXRobkNyZWRlbnRpYWxzLmNyZWRlbnRpYWxJZCwgQnVmZmVyLmZyb20oYHRvdHBfdGVtcF8ke3VzZXJJZH1gKS50b1N0cmluZygnYmFzZTY0dXJsJykpXG4gICAgICAgICk7XG5cbiAgICAgIC8vIEhhYmlsaXRhciBNRkEgbm8gdXN1w6FyaW9cbiAgICAgIGF3YWl0IGRiXG4gICAgICAgIC51cGRhdGUoc2NoZW1hLnVzZXJzKVxuICAgICAgICAuc2V0KHtcbiAgICAgICAgICBtZmFFbmFibGVkOiB0cnVlLFxuICAgICAgICAgIHN0YXR1czogJ2FjdGl2ZScsXG4gICAgICAgICAgdXBkYXRlZEF0OiBuZXcgRGF0ZSgpLFxuICAgICAgICB9KVxuICAgICAgICAud2hlcmUoZXEoc2NoZW1hLnVzZXJzLmlkLCB1c2VySWQpKTtcblxuICAgICAgLy8gR2VyYXIgcmVjb3ZlcnkgY29kZXNcbiAgICAgIGNvbnN0IHJlY292ZXJ5Q29kZXMgPSBnZW5lcmF0ZVJlY292ZXJ5Q29kZXMoQVVUSF9DT05TVEFOVFMuUkVDT1ZFUllfQ09ERV9DT1VOVCk7XG5cbiAgICAgIC8vIFNhbHZhciByZWNvdmVyeSBjb2RlcyBoYXNoZWFkb3NcbiAgICAgIGZvciAoY29uc3QgY29kZSBvZiByZWNvdmVyeUNvZGVzKSB7XG4gICAgICAgIGNvbnN0IGhhc2hlZENvZGUgPSBhd2FpdCBzaGEyNTYoY29kZSk7XG4gICAgICAgIGNvbnN0IGNvZGVQcmVmaXggPSBjb2RlLnN1YnN0cmluZygwLCA0KTsgLy8gUHJpbWVpcm9zIDQgY2FyYWN0ZXJlcyBwYXJhIGlkZW50aWZpY2HDp8Ojb1xuICAgICAgICBjb25zdCBuZXdSZWNvdmVyeUNvZGU6IE5ld1JlY292ZXJ5Q29kZSA9IHtcbiAgICAgICAgICBpZDogZ2VuZXJhdGVVVUlEKCksXG4gICAgICAgICAgdXNlcklkLFxuICAgICAgICAgIGNvZGVIYXNoOiBoYXNoZWRDb2RlLFxuICAgICAgICAgIGNvZGVQcmVmaXgsXG4gICAgICAgICAgdXNlZEF0OiBudWxsLFxuICAgICAgICAgIGNyZWF0ZWRBdDogbmV3IERhdGUoKSxcbiAgICAgICAgfTtcblxuICAgICAgICBhd2FpdCBkYi5pbnNlcnQoc2NoZW1hLnJlY292ZXJ5Q29kZXMpLnZhbHVlcyhuZXdSZWNvdmVyeUNvZGUpO1xuICAgICAgfVxuXG4gICAgICAvLyBBdWRpdG9yaWFcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdNRkFfRU5BQkxFRCcsXG4gICAgICAgIHVzZXJJZCxcbiAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICByZWNvdmVyeUNvZGVzLFxuICAgICAgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgY29uc29sZS5lcnJvcignRXJybyBhbyB2ZXJpZmljYXIgc2V0dXAgTUZBOicsIGVycm9yKTtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBlcnJvcjogeyBjb2RlOiAnSU5URVJOQUxfRVJST1InLCBtZXNzYWdlOiBBVVRIX0NPTlNUQU5UUy5FUlJPUl9NRVNTQUdFUy5JTlRFUk5BTF9FUlJPUiB9LFxuICAgICAgfTtcbiAgICB9XG4gIH0sXG5cbiAgLyoqXG4gICAqIFZlcmlmaWNhIGPDs2RpZ28gVE9UUCBkdXJhbnRlIGxvZ2luXG4gICAqL1xuICBhc3luYyB2ZXJpZnlUT1RQKFxuICAgIHVzZXJJZDogc3RyaW5nLFxuICAgIHRvdHBDb2RlOiBzdHJpbmdcbiAgKTogUHJvbWlzZTx7IHN1Y2Nlc3M6IGJvb2xlYW47IGVycm9yPzogYW55IH0+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG5cbiAgICB0cnkge1xuICAgICAgLy8gQnVzY2FyIHVzdcOhcmlvIHBhcmEgb2J0ZXIgc2VjcmV0XG4gICAgICBjb25zdCB1c2VycyA9IGF3YWl0IGRiXG4gICAgICAgIC5zZWxlY3QoKVxuICAgICAgICAuZnJvbShzY2hlbWEudXNlcnMpXG4gICAgICAgIC53aGVyZShlcShzY2hlbWEudXNlcnMuaWQsIHVzZXJJZCkpXG4gICAgICAgIC5saW1pdCgxKTtcblxuICAgICAgaWYgKCF1c2VycyB8fCB1c2Vycy5sZW5ndGggPT09IDApIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICBlcnJvcjogeyBjb2RlOiAnVVNFUl9OT1RfRk9VTkQnLCBtZXNzYWdlOiAnVXN1w6FyaW8gbsOjbyBlbmNvbnRyYWRvJyB9LFxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICBjb25zdCB1c2VyID0gdXNlcnNbMF07XG5cbiAgICAgIGlmICghdXNlci5tZmFFbmFibGVkKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgZXJyb3I6IHsgY29kZTogJ01GQV9OT1RfRU5BQkxFRCcsIG1lc3NhZ2U6ICdNRkEgbsOjbyBoYWJpbGl0YWRvJyB9LFxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICAvLyBCdXNjYXIgY3JlZGVuY2lhaXMgV2ViQXV0aG4gKHF1ZSBhcm1hemVuYW0gbyBzZWNyZXQgVE9UUClcbiAgICAgIGNvbnN0IGNyZWRlbnRpYWxzID0gYXdhaXQgZGJcbiAgICAgICAgLnNlbGVjdCgpXG4gICAgICAgIC5mcm9tKHNjaGVtYS53ZWJhdXRobkNyZWRlbnRpYWxzKVxuICAgICAgICAud2hlcmUoXG4gICAgICAgICAgZXEoc2NoZW1hLndlYmF1dGhuQ3JlZGVudGlhbHMudXNlcklkLCB1c2VySWQpXG4gICAgICAgIClcbiAgICAgICAgLmxpbWl0KDEpO1xuXG4gICAgICBpZiAoIWNyZWRlbnRpYWxzIHx8IGNyZWRlbnRpYWxzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgIGVycm9yOiB7IGNvZGU6ICdNRkFfQ1JFREVOVElBTF9OT1RfRk9VTkQnLCBtZXNzYWdlOiAnQ3JlZGVuY2lhbCBNRkEgbsOjbyBlbmNvbnRyYWRhJyB9LFxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICBjb25zdCBzZWNyZXQgPSBjcmVkZW50aWFsc1swXS5wdWJsaWNLZXk7XG5cbiAgICAgIC8vIFZlcmlmaWNhciBjw7NkaWdvXG4gICAgICBjb25zdCBpc1ZhbGlkID0gdmVyaWZ5VE9UUCh0b3RwQ29kZSwgc2VjcmV0KTtcblxuICAgICAgaWYgKCFpc1ZhbGlkKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgZXJyb3I6IHsgY29kZTogJ0lOVkFMSURfVE9UUF9DT0RFJywgbWVzc2FnZTogJ0PDs2RpZ28gVE9UUCBpbnbDoWxpZG8nIH0sXG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IHRydWUgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgY29uc29sZS5lcnJvcignRXJybyBhbyB2ZXJpZmljYXIgVE9UUDonLCBlcnJvcik7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZXJyb3I6IHsgY29kZTogJ0lOVEVSTkFMX0VSUk9SJywgbWVzc2FnZTogQVVUSF9DT05TVEFOVFMuRVJST1JfTUVTU0FHRVMuSU5URVJOQUxfRVJST1IgfSxcbiAgICAgIH07XG4gICAgfVxuICB9LFxuXG4gIC8qKlxuICAgKiBVc2EgcmVjb3ZlcnkgY29kZSBwYXJhIGF1dGVudGljYXJcbiAgICovXG4gIGFzeW5jIHVzZVJlY292ZXJ5Q29kZShcbiAgICB1c2VySWQ6IHN0cmluZyxcbiAgICByZWNvdmVyeUNvZGU6IHN0cmluZyxcbiAgICBpcEFkZHJlc3M6IHN0cmluZyxcbiAgICB1c2VyQWdlbnQ6IHN0cmluZ1xuICApOiBQcm9taXNlPHsgc3VjY2VzczogYm9vbGVhbjsgZXJyb3I/OiBhbnkgfT4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcblxuICAgIHRyeSB7XG4gICAgICBjb25zdCBoYXNoZWRDb2RlID0gYXdhaXQgc2hhMjU2KHJlY292ZXJ5Q29kZSk7XG5cbiAgICAgIC8vIEJ1c2NhciByZWNvdmVyeSBjb2RlXG4gICAgICBjb25zdCBjb2RlcyA9IGF3YWl0IGRiXG4gICAgICAgIC5zZWxlY3QoKVxuICAgICAgICAuZnJvbShzY2hlbWEucmVjb3ZlcnlDb2RlcylcbiAgICAgICAgLndoZXJlKFxuICAgICAgICAgIGVxKHNjaGVtYS5yZWNvdmVyeUNvZGVzLmNvZGVIYXNoLCBoYXNoZWRDb2RlKVxuICAgICAgICApXG4gICAgICAgIC5saW1pdCgxKTtcblxuICAgICAgaWYgKCFjb2RlcyB8fCBjb2Rlcy5sZW5ndGggPT09IDApIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICBlcnJvcjogeyBjb2RlOiAnSU5WQUxJRF9SRUNPVkVSWV9DT0RFJywgbWVzc2FnZTogJ1JlY292ZXJ5IGNvZGUgaW52w6FsaWRvJyB9LFxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICBjb25zdCBjb2RlID0gY29kZXNbMF07XG5cbiAgICAgIC8vIFZlcmlmaWNhciBzZSBqw6EgZm9pIHVzYWRvXG4gICAgICBpZiAoY29kZS51c2VkQXQgIT09IG51bGwpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICBlcnJvcjogeyBjb2RlOiAnUkVDT1ZFUllfQ09ERV9VU0VEJywgbWVzc2FnZTogJ1JlY292ZXJ5IGNvZGUgasOhIHV0aWxpemFkbycgfSxcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgLy8gVmVyaWZpY2FyIHNlIHBlcnRlbmNlIGFvIHVzdcOhcmlvXG4gICAgICBpZiAoY29kZS51c2VySWQgIT09IHVzZXJJZCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlZBTElEX1JFQ09WRVJZX0NPREUnLCBtZXNzYWdlOiAnUmVjb3ZlcnkgY29kZSBpbnbDoWxpZG8nIH0sXG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIC8vIE1hcmNhciBjb21vIHVzYWRvXG4gICAgICBhd2FpdCBkYlxuICAgICAgICAudXBkYXRlKHNjaGVtYS5yZWNvdmVyeUNvZGVzKVxuICAgICAgICAuc2V0KHtcbiAgICAgICAgICB1c2VkQXQ6IG5ldyBEYXRlKCksXG4gICAgICAgIH0pXG4gICAgICAgIC53aGVyZShlcShzY2hlbWEucmVjb3ZlcnlDb2Rlcy5pZCwgY29kZS5pZCkpO1xuXG4gICAgICAvLyBBdWRpdG9yaWFcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdSRUNPVkVSWV9DT0RFX1VTRUQnLFxuICAgICAgICB1c2VySWQsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgIG1ldGFkYXRhOiB7IGNvZGVJZDogY29kZS5pZCB9LFxuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IHRydWUgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgY29uc29sZS5lcnJvcignRXJybyBhbyB1c2FyIHJlY292ZXJ5IGNvZGU6JywgZXJyb3IpO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlRFUk5BTF9FUlJPUicsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLklOVEVSTkFMX0VSUk9SIH0sXG4gICAgICB9O1xuICAgIH1cbiAgfSxcblxuICAvKipcbiAgICogR2VyYSBub3ZvcyByZWNvdmVyeSBjb2RlcyAocmVxdWVyIGF1dGVudGljYcOnw6NvIHByw6l2aWEpXG4gICAqL1xuICBhc3luYyByZWdlbmVyYXRlUmVjb3ZlcnlDb2RlcyhcbiAgICB1c2VySWQ6IHN0cmluZyxcbiAgICBpcEFkZHJlc3M6IHN0cmluZyxcbiAgICB1c2VyQWdlbnQ6IHN0cmluZ1xuICApOiBQcm9taXNlPHsgc3VjY2VzczogYm9vbGVhbjsgcmVjb3ZlcnlDb2Rlcz86IHN0cmluZ1tdOyBlcnJvcj86IGFueSB9PiB7XG4gICAgY29uc3QgZGIgPSBnZXREQigpO1xuXG4gICAgdHJ5IHtcbiAgICAgIC8vIEludmFsaWRhciB0b2RvcyBvcyByZWNvdmVyeSBjb2RlcyBleGlzdGVudGVzXG4gICAgICBhd2FpdCBkYlxuICAgICAgICAudXBkYXRlKHNjaGVtYS5yZWNvdmVyeUNvZGVzKVxuICAgICAgICAuc2V0KHtcbiAgICAgICAgICB1c2VkQXQ6IG5ldyBEYXRlKCksIC8vIE1hcmNhciB0b2RvcyBjb21vIFwidXNhZG9zXCIgcGFyYSBpbnZhbGlkYXJcbiAgICAgICAgfSlcbiAgICAgICAgLndoZXJlKGVxKHNjaGVtYS5yZWNvdmVyeUNvZGVzLnVzZXJJZCwgdXNlcklkKSk7XG5cbiAgICAgIC8vIEdlcmFyIG5vdm9zIGNvZGVzXG4gICAgICBjb25zdCByZWNvdmVyeUNvZGVzID0gZ2VuZXJhdGVSZWNvdmVyeUNvZGVzKEFVVEhfQ09OU1RBTlRTLlJFQ09WRVJZX0NPREVfQ09VTlQpO1xuXG4gICAgICAvLyBTYWx2YXIgbm92b3MgY29kZXMgaGFzaGVhZG9zXG4gICAgICBmb3IgKGNvbnN0IGNvZGUgb2YgcmVjb3ZlcnlDb2Rlcykge1xuICAgICAgICBjb25zdCBoYXNoZWRDb2RlID0gYXdhaXQgc2hhMjU2KGNvZGUpO1xuICAgICAgICBjb25zdCBjb2RlUHJlZml4ID0gY29kZS5zdWJzdHJpbmcoMCwgNCk7IC8vIFByaW1laXJvcyA0IGNhcmFjdGVyZXMgcGFyYSBpZGVudGlmaWNhw6fDo29cbiAgICAgICAgY29uc3QgbmV3UmVjb3ZlcnlDb2RlOiBOZXdSZWNvdmVyeUNvZGUgPSB7XG4gICAgICAgICAgaWQ6IGdlbmVyYXRlVVVJRCgpLFxuICAgICAgICAgIHVzZXJJZCxcbiAgICAgICAgICBjb2RlSGFzaDogaGFzaGVkQ29kZSxcbiAgICAgICAgICBjb2RlUHJlZml4LFxuICAgICAgICAgIHVzZWRBdDogbnVsbCxcbiAgICAgICAgICBjcmVhdGVkQXQ6IG5ldyBEYXRlKCksXG4gICAgICAgIH07XG5cbiAgICAgICAgYXdhaXQgZGIuaW5zZXJ0KHNjaGVtYS5yZWNvdmVyeUNvZGVzKS52YWx1ZXMobmV3UmVjb3ZlcnlDb2RlKTtcbiAgICAgIH1cblxuICAgICAgLy8gQXVkaXRvcmlhXG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnUkVDT1ZFUllfQ09ERVNfUkVHRU5FUkFURUQnLFxuICAgICAgICB1c2VySWQsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgcmVjb3ZlcnlDb2RlcyxcbiAgICAgIH07XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm8gYW8gcmVnZW5lcmFyIHJlY292ZXJ5IGNvZGVzOicsIGVycm9yKTtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBlcnJvcjogeyBjb2RlOiAnSU5URVJOQUxfRVJST1InLCBtZXNzYWdlOiBBVVRIX0NPTlNUQU5UUy5FUlJPUl9NRVNTQUdFUy5JTlRFUk5BTF9FUlJPUiB9LFxuICAgICAgfTtcbiAgICB9XG4gIH0sXG5cbiAgLyoqXG4gICAqIERlc2FiaWxpdGEgTUZBIGRvIHVzdcOhcmlvIChvcGVyYcOnw6NvIGRlIGFsdG8gcmlzY28pXG4gICAqL1xuICBhc3luYyBkaXNhYmxlTUZBKFxuICAgIHVzZXJJZDogc3RyaW5nLFxuICAgIHBhc3N3b3JkOiBzdHJpbmcsXG4gICAgaXBBZGRyZXNzOiBzdHJpbmcsXG4gICAgdXNlckFnZW50OiBzdHJpbmdcbiAgKTogUHJvbWlzZTx7IHN1Y2Nlc3M6IGJvb2xlYW47IGVycm9yPzogYW55IH0+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG5cbiAgICB0cnkge1xuICAgICAgY29uc3QgdXNlcnMgPSBhd2FpdCBkYlxuICAgICAgICAuc2VsZWN0KHsgcGFzc3dvcmRIYXNoOiBzY2hlbWEudXNlcnMucGFzc3dvcmRIYXNoIH0pXG4gICAgICAgIC5mcm9tKHNjaGVtYS51c2VycylcbiAgICAgICAgLndoZXJlKGVxKHNjaGVtYS51c2Vycy5pZCwgdXNlcklkKSlcbiAgICAgICAgLmxpbWl0KDEpO1xuXG4gICAgICBpZiAoIXVzZXJzIHx8IHVzZXJzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgIGVycm9yOiB7IGNvZGU6ICdVU0VSX05PVF9GT1VORCcsIG1lc3NhZ2U6ICdVc3XDoXJpbyBuw6NvIGVuY29udHJhZG8nIH0sXG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIC8vIFRPRE86IFZlcmlmaWNhciBzZW5oYSBhcXVpIChpbXBvcnRhciBhcmdvbjJpZFZlcmlmeSlcbiAgICAgIC8vIFBvciBlbnF1YW50bywgYXBlbmFzIGRlc2FiaWxpdGEgTUZBXG5cbiAgICAgIGF3YWl0IGRiXG4gICAgICAgIC51cGRhdGUoc2NoZW1hLnVzZXJzKVxuICAgICAgICAuc2V0KHtcbiAgICAgICAgICBtZmFFbmFibGVkOiBmYWxzZSxcbiAgICAgICAgICBzdGF0dXM6ICdwZW5kaW5nX21mYScsXG4gICAgICAgICAgdXBkYXRlZEF0OiBuZXcgRGF0ZSgpLFxuICAgICAgICB9KVxuICAgICAgICAud2hlcmUoZXEoc2NoZW1hLnVzZXJzLmlkLCB1c2VySWQpKTtcblxuICAgICAgLy8gUmVtb3ZlciBjcmVkZW5jaWFpcyBUT1RQXG4gICAgICBhd2FpdCBkYlxuICAgICAgICAuZGVsZXRlKHNjaGVtYS53ZWJhdXRobkNyZWRlbnRpYWxzKVxuICAgICAgICAud2hlcmUoZXEoc2NoZW1hLndlYmF1dGhuQ3JlZGVudGlhbHMudXNlcklkLCB1c2VySWQpKTtcblxuICAgICAgLy8gSW52YWxpZGFyIHJlY292ZXJ5IGNvZGVzXG4gICAgICBhd2FpdCBkYlxuICAgICAgICAudXBkYXRlKHNjaGVtYS5yZWNvdmVyeUNvZGVzKVxuICAgICAgICAuc2V0KHtcbiAgICAgICAgICB1c2VkQXQ6IG5ldyBEYXRlKCksXG4gICAgICAgIH0pXG4gICAgICAgIC53aGVyZShlcShzY2hlbWEucmVjb3ZlcnlDb2Rlcy51c2VySWQsIHVzZXJJZCkpO1xuXG4gICAgICAvLyBBdWRpdG9yaWFcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdNRkFfRElTQUJMRUQnLFxuICAgICAgICB1c2VySWQsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIHsgc3VjY2VzczogdHJ1ZSB9O1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdFcnJvIGFvIGRlc2FiaWxpdGFyIE1GQTonLCBlcnJvcik7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZXJyb3I6IHsgY29kZTogJ0lOVEVSTkFMX0VSUk9SJywgbWVzc2FnZTogQVVUSF9DT05TVEFOVFMuRVJST1JfTUVTU0FHRVMuSU5URVJOQUxfRVJST1IgfSxcbiAgICAgIH07XG4gICAgfVxuICB9LFxuXG4gIGFzeW5jIGF1ZGl0TG9nKGV2ZW50OiBBdXRoQXVkaXRFdmVudCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcbiAgICBcbiAgICB0cnkge1xuICAgICAgYXdhaXQgZGIuaW5zZXJ0KHNjaGVtYS5hdWRpdExvZ3MpLnZhbHVlcyh7XG4gICAgICAgIGlkOiBnZW5lcmF0ZVVVSUQoKSxcbiAgICAgICAgYWN0aW9uOiBldmVudC5hY3Rpb24sXG4gICAgICAgIHVzZXJJZDogZXZlbnQudXNlcklkIHx8IG51bGwsXG4gICAgICAgIHNlc3Npb25JZDogZXZlbnQuc2Vzc2lvbklkIHx8IG51bGwsXG4gICAgICAgIGRldmljZUlkOiBldmVudC5kZXZpY2VJZCB8fCBudWxsLFxuICAgICAgICB0aW1lc3RhbXA6IGV2ZW50LnRpbWVzdGFtcCxcbiAgICAgICAgaXBBZGRyZXNzOiBldmVudC5pcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudDogZXZlbnQudXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiBldmVudC5zdWNjZXNzLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiBldmVudC5mYWlsdXJlUmVhc29uIHx8IG51bGwsXG4gICAgICAgIG1ldGFkYXRhOiBldmVudC5tZXRhZGF0YSA/IEpTT04uc3RyaW5naWZ5KGV2ZW50Lm1ldGFkYXRhKSA6IG51bGwsXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgY29uc29sZS5lcnJvcignRXJybyBhbyBjcmlhciBsb2cgZGUgYXVkaXRvcmlhOicsIGVycm9yKTtcbiAgICB9XG4gIH0sXG59O1xuIl19
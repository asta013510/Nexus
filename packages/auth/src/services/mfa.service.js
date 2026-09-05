"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.MFAService = void 0;
exports.setDatabaseClient = setDatabaseClient;
const drizzle_orm_1 = require("drizzle-orm");
const crypto_1 = require("@zero/crypto");
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
exports.MFAService = {
    /**
     * Inicia setup de MFA para usuário
     * Retorna secret TOTP e QR code URI
     */
    async initiateMFASetup(userId, emailAddress) {
        const db = getDB();
        try {
            // Verificar se usuário já tem MFA habilitado
            const users = await db
                .select({ mfaEnabled: database_1.schema.users.mfaEnabled })
                .from(database_1.schema.users)
                .where((0, drizzle_orm_1.eq)(database_1.schema.users.id, userId))
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
            const totpSecret = (0, crypto_1.generateTOTP)();
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
            await db.insert(database_1.schema.webauthnCredentials).values({
                id: (0, shared_1.generateUUID)(),
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
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
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
                .from(database_1.schema.webauthnCredentials)
                .where((0, drizzle_orm_1.eq)(database_1.schema.webauthnCredentials.credentialId, Buffer.from(`totp_temp_${userId}`).toString('base64url')))
                .limit(1);
            if (!credentials || credentials.length === 0) {
                return {
                    success: false,
                    error: { code: 'MFA_SETUP_NOT_INITIATED', message: 'Setup de MFA não iniciado' },
                };
            }
            const secret = credentials[0].publicKey;
            // Verificar código TOTP
            const isValid = (0, crypto_1.verifyTOTP)(totpCode, secret);
            if (!isValid) {
                return {
                    success: false,
                    error: { code: 'INVALID_TOTP_CODE', message: 'Código TOTP inválido' },
                };
            }
            // MFA verificado com sucesso
            // Remover credential temporária
            await db
                .delete(database_1.schema.webauthnCredentials)
                .where((0, drizzle_orm_1.eq)(database_1.schema.webauthnCredentials.credentialId, Buffer.from(`totp_temp_${userId}`).toString('base64url')));
            // Habilitar MFA no usuário
            await db
                .update(database_1.schema.users)
                .set({
                mfaEnabled: true,
                status: 'active',
                updatedAt: new Date(),
            })
                .where((0, drizzle_orm_1.eq)(database_1.schema.users.id, userId));
            // Gerar recovery codes
            const recoveryCodes = (0, crypto_1.generateRecoveryCodes)(constants_1.AUTH_CONSTANTS.RECOVERY_CODE_COUNT);
            // Salvar recovery codes hasheados
            for (const code of recoveryCodes) {
                const hashedCode = await (0, crypto_1.sha256)(code);
                const newRecoveryCode = {
                    id: (0, shared_1.generateUUID)(),
                    userId,
                    codeHash: hashedCode,
                    usedAt: null,
                    createdAt: new Date(),
                };
                await db.insert(database_1.schema.recoveryCodes).values(newRecoveryCode);
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
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
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
                .from(database_1.schema.users)
                .where((0, drizzle_orm_1.eq)(database_1.schema.users.id, userId))
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
                .from(database_1.schema.webauthnCredentials)
                .where((0, drizzle_orm_1.eq)(database_1.schema.webauthnCredentials.userId, userId))
                .limit(1);
            if (!credentials || credentials.length === 0) {
                return {
                    success: false,
                    error: { code: 'MFA_CREDENTIAL_NOT_FOUND', message: 'Credencial MFA não encontrada' },
                };
            }
            const secret = credentials[0].publicKey;
            // Verificar código
            const isValid = (0, crypto_1.verifyTOTP)(totpCode, secret);
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
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    /**
     * Usa recovery code para autenticar
     */
    async useRecoveryCode(userId, recoveryCode, ipAddress, userAgent) {
        const db = getDB();
        try {
            const hashedCode = await (0, crypto_1.sha256)(recoveryCode);
            // Buscar recovery code
            const codes = await db
                .select()
                .from(database_1.schema.recoveryCodes)
                .where((0, drizzle_orm_1.eq)(database_1.schema.recoveryCodes.codeHash, hashedCode))
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
                .update(database_1.schema.recoveryCodes)
                .set({
                usedAt: new Date(),
            })
                .where((0, drizzle_orm_1.eq)(database_1.schema.recoveryCodes.id, code.id));
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
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
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
                .update(database_1.schema.recoveryCodes)
                .set({
                usedAt: new Date(), // Marcar todos como "usados" para invalidar
            })
                .where((0, drizzle_orm_1.eq)(database_1.schema.recoveryCodes.userId, userId));
            // Gerar novos codes
            const recoveryCodes = (0, crypto_1.generateRecoveryCodes)(constants_1.AUTH_CONSTANTS.RECOVERY_CODE_COUNT);
            // Salvar novos codes hasheados
            for (const code of recoveryCodes) {
                const hashedCode = await (0, crypto_1.sha256)(code);
                const newRecoveryCode = {
                    id: (0, shared_1.generateUUID)(),
                    userId,
                    codeHash: hashedCode,
                    usedAt: null,
                    createdAt: new Date(),
                };
                await db.insert(database_1.schema.recoveryCodes).values(newRecoveryCode);
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
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
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
                .select({ passwordHash: database_1.schema.users.passwordHash })
                .from(database_1.schema.users)
                .where((0, drizzle_orm_1.eq)(database_1.schema.users.id, userId))
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
                .update(database_1.schema.users)
                .set({
                mfaEnabled: false,
                status: 'pending_mfa',
                updatedAt: new Date(),
            })
                .where((0, drizzle_orm_1.eq)(database_1.schema.users.id, userId));
            // Remover credenciais TOTP
            await db
                .delete(database_1.schema.webauthnCredentials)
                .where((0, drizzle_orm_1.eq)(database_1.schema.webauthnCredentials.userId, userId));
            // Invalidar recovery codes
            await db
                .update(database_1.schema.recoveryCodes)
                .set({
                usedAt: new Date(),
            })
                .where((0, drizzle_orm_1.eq)(database_1.schema.recoveryCodes.userId, userId));
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
//# sourceMappingURL=mfa.service.js.map
"use strict";
/**
 * Serviço de Autenticação Principal
 *
 * Responsabilidades:
 * - Registro de usuários
 * - Login com validação de credenciais
 * - Gerenciamento de tentativas e lockout
 * - Integração com MFA
 * - Auditoria de eventos
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
exports.setDatabaseClient = setDatabaseClient;
const drizzle_orm_1 = require("drizzle-orm");
const crypto_1 = require("@zero/crypto");
const database_1 = require("@zero/database");
const shared_1 = require("@zero/shared");
const constants_1 = require("../constants");
const validation_1 = require("../utils/validation");
const tokens_1 = require("../utils/tokens");
// Mock do database client (será injetado pela API)
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
/**
 * Registra novo usuário no sistema
 *
 * SECURITY NOTES:
 * - Email normalizado para lowercase
 * - Senha hash com Argon2id antes de armazenar
 * - Validação de força da senha
 * - Verificação de email duplicado
 * - Geração de recovery codes
 * - Auditoria do evento
 */
exports.AuthService = {
    async register(input, ipAddress, userAgent) {
        const db = getDB();
        // Audit: registro iniciado
        await this.auditLog({
            action: 'REGISTER_REQUEST',
            timestamp: new Date(),
            ipAddress,
            userAgent,
            success: true,
            metadata: { email: input.email },
        });
        // Validar email
        const emailValidation = (0, validation_1.validateEmail)(input.email);
        if (!emailValidation.valid) {
            await this.auditLog({
                action: 'REGISTER_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: emailValidation.error?.message,
            });
            return { success: false, error: emailValidation.error };
        }
        // Validar senha
        const passwordValidation = (0, validation_1.validatePassword)(input.password);
        if (!passwordValidation.valid) {
            await this.auditLog({
                action: 'REGISTER_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: passwordValidation.error?.message,
            });
            return { success: false, error: passwordValidation.error };
        }
        const normalizedEmail = (0, validation_1.normalizeEmail)(input.email);
        // Verificar se email já existe
        try {
            const existingUser = await db
                .select()
                .from(database_1.schema.users)
                .where((0, drizzle_orm_1.eq)(database_1.schema.users.email, normalizedEmail))
                .limit(1);
            if (existingUser && existingUser.length > 0) {
                await this.auditLog({
                    action: 'REGISTER_FAILURE',
                    timestamp: new Date(),
                    ipAddress,
                    userAgent,
                    success: false,
                    failureReason: 'Email já cadastrado',
                });
                return {
                    success: false,
                    error: { code: 'EMAIL_ALREADY_EXISTS', message: 'Email já cadastrado' },
                };
            }
        }
        catch (error) {
            await this.auditLog({
                action: 'REGISTER_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Erro ao verificar email',
            });
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
        // Hash da senha com Argon2id
        let passwordHash;
        try {
            passwordHash = await (0, crypto_1.hashPassword)(input.password);
        }
        catch (error) {
            await this.auditLog({
                action: 'REGISTER_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Erro ao hash senha',
            });
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
        // Criar usuário
        const userId = (0, shared_1.generateUUID)();
        const salt = (0, crypto_1.generateSalt)();
        const newUser = {
            id: userId,
            email: normalizedEmail,
            passwordHash: hash,
            passwordSalt: salt,
            displayName: input.displayName?.trim() || null,
            recoveryEmail: input.recoveryEmail ? (0, validation_1.normalizeEmail)(input.recoveryEmail) : null,
            status: 'pending_mfa', // Requer setup de MFA após registro
            mfaEnabled: false,
            createdAt: new Date(),
            updatedAt: new Date(),
            failedLoginAttempts: 0,
            lockedUntil: null,
            lastLoginAt: null,
            facialTemplateHash: null, // Será definido se usar biometria
        };
        try {
            await db.insert(database_1.schema.users).values(newUser);
            // TODO: Gerar recovery codes e salvar em encryption_keys
            await this.auditLog({
                action: 'REGISTER_SUCCESS',
                userId,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: true,
            });
            return {
                success: true,
                userId,
                requiresMFA: true,
            };
        }
        catch (error) {
            await this.auditLog({
                action: 'REGISTER_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Erro ao criar usuário',
            });
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    /**
     * Autentica usuário com email e senha
     *
     * SECURITY NOTES:
     * - Timing-safe comparison para senha
     * - Rate limiting por IP e usuário
     * - Lockout após múltiplas falhas
     * - Mensagens de erro genéricas (não revelar se email existe)
     * - Requer MFA se habilitado
     */
    async login(input, ipAddress, userAgent) {
        const db = getDB();
        // Audit: login iniciado
        await this.auditLog({
            action: 'LOGIN_REQUEST',
            timestamp: new Date(),
            ipAddress,
            userAgent,
            success: true,
            metadata: { email: input.email },
        });
        // Validar formato do email
        const emailValidation = (0, validation_1.validateEmail)(input.email);
        if (!emailValidation.valid) {
            await this.auditLog({
                action: 'LOGIN_FAILURE_PASSWORD',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Email inválido',
            });
            return {
                success: false,
                error: { code: 'INVALID_CREDENTIALS', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INVALID_CREDENTIALS },
            };
        }
        const normalizedEmail = (0, validation_1.normalizeEmail)(input.email);
        // Buscar usuário
        let user = null;
        try {
            const users = await db
                .select()
                .from(database_1.schema.users)
                .where((0, drizzle_orm_1.eq)(database_1.schema.users.email, normalizedEmail))
                .limit(1);
            user = users && users.length > 0 ? users[0] : null;
        }
        catch (error) {
            await this.auditLog({
                action: 'LOGIN_FAILURE_PASSWORD',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Erro ao buscar usuário',
            });
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
        // Se usuário não existir, simular delay para prevenir timing attack
        if (!user) {
            await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 100));
            await this.auditLog({
                action: 'LOGIN_FAILURE_PASSWORD',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Usuário não encontrado',
            });
            return {
                success: false,
                error: { code: 'INVALID_CREDENTIALS', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INVALID_CREDENTIALS },
            };
        }
        // Verificar se conta está bloqueada
        if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
            await this.auditLog({
                action: 'LOGIN_FAILURE_LOCKED',
                userId: user.id,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Conta bloqueada',
            });
            return {
                success: false,
                error: { code: 'USER_LOCKED', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.USER_LOCKED },
            };
        }
        // Verificar senha com timing-safe comparison
        const passwordValid = await argon2idVerify(input.password, user.passwordHash);
        if (!passwordValid) {
            // Incrementar tentativas falhas
            await this.incrementFailedAttempts(user.id);
            await this.auditLog({
                action: 'LOGIN_FAILURE_PASSWORD',
                userId: user.id,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Senha inválida',
            });
            return {
                success: false,
                error: { code: 'INVALID_CREDENTIALS', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INVALID_CREDENTIALS },
            };
        }
        // Resetar tentativas falhas após login bem-sucedido
        await this.resetFailedAttempts(user.id);
        // Verificar se MFA está habilitado
        if (!user.mfaEnabled) {
            // Usuário precisa configurar MFA (estado pending_mfa)
            if (user.status === 'pending_mfa') {
                return {
                    success: true,
                    userId: user.id,
                    requiresMFA: true,
                };
            }
        }
        // Se chegou aqui, senha válida e MFA pode estar habilitado
        // Se MFA habilitado, requer código
        if (user.mfaEnabled) {
            if (!input.mfaCode) {
                return {
                    success: true,
                    userId: user.id,
                    requiresMFA: true,
                };
            }
            // Verificar código MFA será feito pelo MFAService
            // Retornar para o controller chamar o próximo passo
            return {
                success: true,
                userId: user.id,
                requiresMFA: true,
            };
        }
        // MFA não habilitado (deveria ser raro em produção)
        // Criar sessão diretamente
        return await this.createSession(user, input, ipAddress, userAgent);
    },
    /**
     * Cria sessão após autenticação bem-sucedida
     */
    async createSession(user, input, ipAddress, userAgent) {
        const db = getDB();
        try {
            // Gerar tokens JWT
            const sessionId = (0, shared_1.generateUUID)();
            const tokens = await (0, tokens_1.generateAuthTokens)({
                userId: user.id,
                sessionId,
                mfaVerified: user.mfaEnabled || false,
                counter: 0,
            });
            // Salvar sessão no banco
            await db.insert(database_1.schema.sessions).values({
                id: sessionId,
                userId: user.id,
                refreshTokenHash: await (0, crypto_1.sha256)(tokens.refreshToken),
                expiresAt: tokens.expiresAt,
                refreshExpiresAt: tokens.refreshExpiresAt,
                createdAt: new Date(),
                revoked: false,
            });
            // Atualizar último login
            await db
                .update(database_1.schema.users)
                .set({
                lastLoginAt: new Date(),
                updatedAt: new Date(),
            })
                .where((0, drizzle_orm_1.eq)(database_1.schema.users.id, user.id));
            // Criar/atualizar dispositivo
            let deviceId;
            if (input.deviceId) {
                deviceId = input.deviceId;
                await db
                    .update(database_1.schema.devices)
                    .set({
                    lastSeenAt: new Date(),
                    ipAddress,
                    userAgent,
                })
                    .where((0, drizzle_orm_1.eq)(database_1.schema.devices.id, deviceId));
            }
            else {
                // Criar novo dispositivo
                deviceId = (0, shared_1.generateUUID)();
                const deviceType = this.detectDeviceType(userAgent);
                const { os, browser } = this.parseUserAgent(userAgent);
                await db.insert(database_1.schema.devices).values({
                    id: deviceId,
                    userId: user.id,
                    name: `${deviceType} - ${browser} on ${os}`,
                    type: deviceType,
                    os,
                    browser,
                    isTrusted: input.rememberDevice ?? false,
                    trustedUntil: input.rememberDevice
                        ? new Date(Date.now() + constants_1.AUTH_CONSTANTS.TRUSTED_DEVICE_EXPIRY_DAYS * 24 * 60 * 60 * 1000)
                        : null,
                    lastSeenAt: new Date(),
                    ipAddress,
                    userAgent,
                    createdAt: new Date(),
                });
            }
            await this.auditLog({
                action: 'LOGIN_SUCCESS',
                userId: user.id,
                sessionId,
                deviceId,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: true,
            });
            return {
                success: true,
                userId: user.id,
                session: {
                    sessionId,
                    userId: user.id,
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken,
                    expiresAt: tokens.expiresAt,
                    refreshExpiresAt: tokens.refreshExpiresAt,
                    device: {
                        deviceId: deviceId,
                        name: `${deviceType} - ${browser} on ${os}`,
                        type: deviceType,
                        os,
                        browser,
                        isTrusted: input.rememberDevice ?? false,
                        lastSeenAt: new Date(),
                        ipAddress,
                        userAgent,
                    },
                    mfaVerified: user.mfaEnabled || false,
                    createdAt: new Date(),
                },
            };
        }
        catch (error) {
            await this.auditLog({
                action: 'LOGIN_FAILURE_PASSWORD',
                userId: user.id,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Erro ao criar sessão',
            });
            return {
                success: false,
                error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    /**
     * Incrementa tentativas falhas e aplica lockout se necessário
     */
    async incrementFailedAttempts(userId) {
        const db = getDB();
        await db
            .update(database_1.schema.users)
            .set({
            failedLoginAttempts: (0, drizzle_orm_2.sql) `${database_1.schema.users.failedLoginAttempts} + 1`,
            lockedUntil: (0, drizzle_orm_2.sql) `CASE 
          WHEN ${database_1.schema.users.failedLoginAttempts} + 1 >= ${constants_1.AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS}
          THEN NOW() + INTERVAL '${constants_1.AUTH_CONSTANTS.LOCKOUT_DURATION} seconds'
          ELSE ${database_1.schema.users.lockedUntil}
        END`,
            updatedAt: new Date(),
        })
            .where((0, drizzle_orm_1.eq)(database_1.schema.users.id, userId));
    },
    /**
     * Reset tentativas falhas após login bem-sucedido
     */
    async resetFailedAttempts(userId) {
        const db = getDB();
        await db
            .update(database_1.schema.users)
            .set({
            failedLoginAttempts: 0,
            lockedUntil: null,
            updatedAt: new Date(),
        })
            .where((0, drizzle_orm_1.eq)(database_1.schema.users.id, userId));
    },
    /**
     * Detecta tipo de dispositivo a partir do user agent
     */
    detectDeviceType(userAgent) {
        const ua = userAgent.toLowerCase();
        if (/mobile|android|iphone|ipod|blackberry|windows phone/i.test(ua)) {
            return 'mobile';
        }
        if (/tablet|ipad|silk|kindle/i.test(ua)) {
            return 'tablet';
        }
        if (/desktop|windows|macintosh|linux|ubuntu/i.test(ua)) {
            return 'desktop';
        }
        return 'unknown';
    },
    /**
     * Parse user agent para extrair OS e browser
     * Implementação simplificada - usar biblioteca dedicada em produção
     */
    parseUserAgent(userAgent) {
        const ua = userAgent.toLowerCase();
        let os = 'Unknown';
        if (/windows nt/i.test(ua))
            os = 'Windows';
        else if (/macintosh|mac os x/i.test(ua))
            os = 'macOS';
        else if (/linux|ubuntu/i.test(ua))
            os = 'Linux';
        else if (/android/i.test(ua))
            os = 'Android';
        else if (/iphone|ipad|ipod/i.test(ua))
            os = 'iOS';
        let browser = 'Unknown';
        if (/chrome|crios/i.test(ua))
            browser = 'Chrome';
        else if (/firefox|fxios/i.test(ua))
            browser = 'Firefox';
        else if (/safari|version\/\d+/i.test(ua) && !/chrome/i.test(ua))
            browser = 'Safari';
        else if (/edg/i.test(ua))
            browser = 'Edge';
        else if (/opera|opr/i.test(ua))
            browser = 'Opera';
        return { os, browser };
    },
    /**
     * Log de auditoria para eventos de autenticação
     */
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
                metadata: event.metadata || null,
            });
        }
        catch (error) {
            // NUNCA falhar autenticação por erro de logging
            console.error('[AuthService] Falha ao registrar log de auditoria:', error);
        }
    },
};
// Import necessário para SQL
const drizzle_orm_2 = require("drizzle-orm");
//# sourceMappingURL=auth.service.js.map
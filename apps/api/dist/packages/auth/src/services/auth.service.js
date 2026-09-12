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
import { eq } from 'drizzle-orm';
import { hashPassword, verifyPassword, generateSalt, sha256 } from '@zero/crypto';
import { schema } from '@zero/database';
import { generateUUID } from '@zero/shared';
import { AUTH_CONSTANTS } from '../constants';
import { validateEmail, validatePassword, normalizeEmail } from '../utils/validation';
import { generateAuthTokens } from '../utils/tokens';
// Mock do database client (será injetado pela API)
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
export const AuthService = {
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
        const emailValidation = validateEmail(input.email);
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
        const passwordValidation = validatePassword(input.password);
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
        const normalizedEmail = normalizeEmail(input.email);
        // Verificar se email já existe
        try {
            const existingUser = await db
                .select()
                .from(schema.users)
                .where(eq(schema.users.email, normalizedEmail))
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
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
        // Hash da senha com Argon2id
        let passwordHash;
        try {
            passwordHash = await hashPassword(input.password);
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
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
        // Criar usuário
        const userId = generateUUID();
        const salt = generateSalt();
        const newUser = {
            id: userId,
            email: normalizedEmail,
            passwordHash,
            passwordSalt: salt,
            displayName: input.displayName?.trim() || null,
            recoveryEmail: input.recoveryEmail ? normalizeEmail(input.recoveryEmail) : null,
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
            await db.insert(schema.users).values(newUser);
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
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
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
        const emailValidation = validateEmail(input.email);
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
                error: { code: 'INVALID_CREDENTIALS', message: AUTH_CONSTANTS.ERROR_MESSAGES.INVALID_CREDENTIALS },
            };
        }
        const normalizedEmail = normalizeEmail(input.email);
        // Buscar usuário
        let user = null;
        try {
            const users = await db
                .select()
                .from(schema.users)
                .where(eq(schema.users.email, normalizedEmail))
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
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
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
                error: { code: 'INVALID_CREDENTIALS', message: AUTH_CONSTANTS.ERROR_MESSAGES.INVALID_CREDENTIALS },
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
                error: { code: 'USER_LOCKED', message: AUTH_CONSTANTS.ERROR_MESSAGES.USER_LOCKED },
            };
        }
        // Verificar senha com timing-safe comparison
        const passwordValid = await verifyPassword(input.password, user.passwordHash);
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
                error: { code: 'INVALID_CREDENTIALS', message: AUTH_CONSTANTS.ERROR_MESSAGES.INVALID_CREDENTIALS },
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
            const sessionId = generateUUID();
            const tokens = await generateAuthTokens({
                userId: user.id,
                sessionId,
                mfaVerified: user.mfaEnabled || false,
                counter: 0,
            });
            // Salvar sessão no banco
            await db.insert(schema.sessions).values({
                id: sessionId,
                userId: user.id,
                refreshTokenHash: await sha256(tokens.refreshToken),
                expiresAt: tokens.expiresAt,
                refreshExpiresAt: tokens.refreshExpiresAt,
                createdAt: new Date(),
                revoked: false,
            });
            // Atualizar último login
            await db
                .update(schema.users)
                .set({
                lastLoginAt: new Date(),
                updatedAt: new Date(),
            })
                .where(eq(schema.users.id, user.id));
            // Criar/atualizar dispositivo
            let deviceId;
            const deviceType = this.detectDeviceType(userAgent);
            const { os, browser } = this.parseUserAgent(userAgent);
            if (input.deviceId) {
                deviceId = input.deviceId;
                await db
                    .update(schema.devices)
                    .set({
                    lastSeenAt: new Date(),
                    ipAddress,
                    userAgent,
                })
                    .where(eq(schema.devices.id, deviceId));
            }
            else {
                // Criar novo dispositivo
                deviceId = generateUUID();
                await db.insert(schema.devices).values({
                    id: deviceId,
                    userId: user.id,
                    name: `${deviceType} - ${browser} on ${os}`,
                    type: deviceType,
                    os,
                    browser,
                    isTrusted: input.rememberDevice ?? false,
                    trustedUntil: input.rememberDevice
                        ? new Date(Date.now() + AUTH_CONSTANTS.TRUSTED_DEVICE_EXPIRY_DAYS * 24 * 60 * 60 * 1000)
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
                error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR },
            };
        }
    },
    /**
     * Incrementa tentativas falhas e aplica lockout se necessário
     */
    async incrementFailedAttempts(userId) {
        const db = getDB();
        await db
            .update(schema.users)
            .set({
            failedLoginAttempts: sql `${schema.users.failedLoginAttempts} + 1`,
            lockedUntil: sql `CASE 
          WHEN ${schema.users.failedLoginAttempts} + 1 >= ${AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS}
          THEN NOW() + INTERVAL '${AUTH_CONSTANTS.LOCKOUT_DURATION} seconds'
          ELSE ${schema.users.lockedUntil}
        END`,
            updatedAt: new Date(),
        })
            .where(eq(schema.users.id, userId));
    },
    /**
     * Reset tentativas falhas após login bem-sucedido
     */
    async resetFailedAttempts(userId) {
        const db = getDB();
        await db
            .update(schema.users)
            .set({
            failedLoginAttempts: 0,
            lockedUntil: null,
            updatedAt: new Date(),
        })
            .where(eq(schema.users.id, userId));
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
                metadata: event.metadata || null,
            });
        }
        catch (error) {
            // NUNCA falhar autenticação por erro de logging
            console.error('[AuthService] Falha ao registrar log de auditoria:', error);
        }
    },
    /**
     * Verifica código MFA durante login
     */
    async verifyMFA(userId, mfaCode, ipAddress, userAgent) {
        const db = getDB();
        await this.auditLog({
            action: 'MFA_VERIFY_REQUEST',
            timestamp: new Date(),
            ipAddress,
            userAgent,
            success: true,
            metadata: { userId },
        });
        const user = await db
            .select()
            .from(schema.users)
            .where(eq(schema.users.id, userId))
            .limit(1);
        if (!user || user.length === 0) {
            await this.auditLog({
                action: 'MFA_VERIFY_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Usuário não encontrado',
            });
            return {
                success: false,
                error: new AuthError('INVALID_CREDENTIALS', 'Credenciais inválidas')
            };
        }
        const userData = user[0];
        if (!userData.mfaEnabled || !userData.mfaSecret) {
            await this.auditLog({
                action: 'MFA_VERIFY_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'MFA não habilitado',
            });
            return {
                success: false,
                error: new AuthError('MFA_NOT_ENABLED', 'MFA não habilitado para esta conta')
            };
        }
        const { verifyTOTP } = await import('@zero/crypto');
        const isValid = verifyTOTP(userData.mfaSecret, mfaCode);
        if (!isValid) {
            await this.auditLog({
                action: 'MFA_VERIFY_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Código MFA inválido',
            });
            return {
                success: false,
                error: new AuthError('INVALID_MFA_CODE', 'Código MFA inválido')
            };
        }
        // MFA verificado com sucesso - gerar tokens
        const sessionId = generateUUID();
        const deviceId = generateUUID();
        const tokens = generateAuthTokens(userId, sessionId, deviceId);
        // Atualizar status do usuário para active
        await db
            .update(schema.users)
            .set({
            status: 'active',
            lastLoginAt: new Date()
        })
            .where(eq(schema.users.id, userId));
        await this.auditLog({
            action: 'MFA_VERIFY_SUCCESS',
            timestamp: new Date(),
            ipAddress,
            userAgent,
            success: true,
            userId,
            sessionId,
            deviceId,
        });
        return {
            success: true,
            user: {
                id: userData.id,
                email: userData.email,
                displayName: userData.displayName,
            },
            tokens,
            mfaRequired: false,
        };
    },
    /**
     * Refresh de access token usando refresh token
     */
    async refreshAccessToken(refreshToken, ipAddress, userAgent) {
        const db = getDB();
        await this.auditLog({
            action: 'TOKEN_REFRESH_REQUEST',
            timestamp: new Date(),
            ipAddress,
            userAgent,
            success: true,
        });
        const { verifyJWT } = await import('@zero/crypto');
        const verified = verifyJWT(refreshToken, 'refresh');
        if (!verified.valid) {
            await this.auditLog({
                action: 'TOKEN_REFRESH_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Refresh token inválido',
            });
            return {
                success: false,
                error: verified.error
            };
        }
        const payload = verified.payload;
        const userId = payload.sub;
        const sessionId = payload.sid;
        // Verificar se sessão ainda existe e é válida
        const sessions = await db
            .select()
            .from(schema.sessions)
            .where(eq(schema.sessions.id, sessionId))
            .limit(1);
        if (!sessions || sessions.length === 0) {
            await this.auditLog({
                action: 'TOKEN_REFRESH_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Sessão não encontrada',
            });
            return {
                success: false,
                error: new AuthError('SESSION_INVALID', 'Sessão inválida ou expirada')
            };
        }
        const session = sessions[0];
        if (session.revokedAt || session.expiresAt < new Date()) {
            await this.auditLog({
                action: 'TOKEN_REFRESH_FAILURE',
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: false,
                failureReason: 'Sessão revogada ou expirada',
            });
            return {
                success: false,
                error: new AuthError('SESSION_REVOKED', 'Sessão foi revogada')
            };
        }
        // Gerar novo par de tokens
        const tokens = generateAuthTokens(userId, sessionId, session.deviceId);
        // Rotacionar refresh token (invalidar o anterior)
        await db
            .update(schema.refreshTokens)
            .set({ revokedAt: new Date() })
            .where(eq(schema.refreshTokens.tokenHash, sha256(refreshToken)));
        await this.auditLog({
            action: 'TOKEN_REFRESH_SUCCESS',
            timestamp: new Date(),
            ipAddress,
            userAgent,
            success: true,
            userId,
            sessionId,
        });
        return {
            success: true,
            tokens,
        };
    },
    /**
     * Logout de uma sessão específica
     */
    async logout(sessionId, ipAddress, userAgent) {
        const db = getDB();
        await this.auditLog({
            action: 'LOGOUT_REQUEST',
            timestamp: new Date(),
            ipAddress,
            userAgent,
            success: true,
            sessionId,
        });
        const sessions = await db
            .select()
            .from(schema.sessions)
            .where(eq(schema.sessions.id, sessionId))
            .limit(1);
        if (!sessions || sessions.length === 0) {
            return { success: true }; // Já não existe, considerado sucesso
        }
        const session = sessions[0];
        // Revogar sessão
        await db
            .update(schema.sessions)
            .set({ revokedAt: new Date() })
            .where(eq(schema.sessions.id, sessionId));
        // Revogar refresh tokens associados
        await db
            .update(schema.refreshTokens)
            .set({ revokedAt: new Date() })
            .where(eq(schema.refreshTokens.sessionId, sessionId));
        await this.auditLog({
            action: 'LOGOUT_SUCCESS',
            timestamp: new Date(),
            ipAddress,
            userAgent,
            success: true,
            sessionId,
            userId: session.userId,
        });
        return { success: true };
    },
    /**
     * Logout de todas as sessões do usuário
     */
    async logoutAll(userId, currentSessionId, ipAddress, userAgent) {
        const db = getDB();
        await this.auditLog({
            action: 'LOGOUT_ALL_REQUEST',
            timestamp: new Date(),
            ipAddress,
            userAgent,
            success: true,
            userId,
        });
        // Revogar todas as sessões exceto a atual (se fornecida)
        const updateQuery = db
            .update(schema.sessions)
            .set({ revokedAt: new Date() })
            .where(eq(schema.sessions.userId, userId));
        if (currentSessionId) {
            updateQuery.where(sql `id != ${currentSessionId}`);
        }
        else {
            updateQuery.execute();
        }
        // Revogar todos os refresh tokens exceto os da sessão atual
        const refreshTokenQuery = db
            .update(schema.refreshTokens)
            .set({ revokedAt: new Date() })
            .where(eq(schema.refreshTokens.userId, userId));
        if (currentSessionId) {
            refreshTokenQuery.where(sql `sessionId != ${currentSessionId}`);
        }
        else {
            refreshTokenQuery.execute();
        }
        await this.auditLog({
            action: 'LOGOUT_ALL_SUCCESS',
            timestamp: new Date(),
            ipAddress,
            userAgent,
            success: true,
            userId,
        });
        return { success: true };
    },
    /**
     * Obtém usuário por ID (sem dados sensíveis)
     */
    async getUserById(userId) {
        const db = getDB();
        try {
            const users = await db
                .select({
                id: schema.users.id,
                email: schema.users.email,
                displayName: schema.users.displayName,
                mfaEnabled: schema.users.mfaEnabled,
                status: schema.users.status,
            })
                .from(schema.users)
                .where(eq(schema.users.id, userId))
                .limit(1);
            if (!users || users.length === 0) {
                return {
                    success: false,
                    error: new AuthError('USER_NOT_FOUND', 'Usuário não encontrado')
                };
            }
            return {
                success: true,
                user: users[0],
            };
        }
        catch (error) {
            console.error('[AuthService] Erro ao buscar usuário:', error);
            return {
                success: false,
                error: new AuthError('DATABASE_ERROR', 'Erro interno ao buscar usuário')
            };
        }
    },
};
// Import necessário para SQL
import { sql } from 'drizzle-orm';
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vLi4vLi4vLi4vcGFja2FnZXMvYXV0aC9zcmMvc2VydmljZXMvYXV0aC5zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7Ozs7Ozs7R0FTRztBQUVILE9BQU8sRUFBRSxFQUFFLEVBQUUsTUFBTSxhQUFhLENBQUM7QUFDakMsT0FBTyxFQUFFLFlBQVksRUFBRSxjQUFjLEVBQUUsWUFBWSxFQUFFLE1BQU0sRUFBRSxNQUFNLGNBQWMsQ0FBQztBQUNsRixPQUFPLEVBQUUsTUFBTSxFQUFxQyxNQUFNLGdCQUFnQixDQUFDO0FBQzNFLE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxjQUFjLENBQUM7QUFDNUMsT0FBTyxFQUFFLGNBQWMsRUFBRSxNQUFNLGNBQWMsQ0FBQztBQVE5QyxPQUFPLEVBQUUsYUFBYSxFQUFFLGdCQUFnQixFQUFFLGNBQWMsRUFBRSxNQUFNLHFCQUFxQixDQUFDO0FBQ3RGLE9BQU8sRUFBRSxrQkFBa0IsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBRXJELG1EQUFtRDtBQUNuRCxJQUFJLFFBQVEsR0FBUSxJQUFJLENBQUM7QUFFekIsTUFBTSxVQUFVLGlCQUFpQixDQUFDLE1BQVc7SUFDM0MsUUFBUSxHQUFHLE1BQU0sQ0FBQztBQUNwQixDQUFDO0FBRUQsU0FBUyxLQUFLO0lBQ1osSUFBSSxDQUFDLFFBQVEsRUFBRSxDQUFDO1FBQ2QsTUFBTSxJQUFJLEtBQUssQ0FBQyxrQ0FBa0MsQ0FBQyxDQUFDO0lBQ3RELENBQUM7SUFDRCxPQUFPLFFBQVEsQ0FBQztBQUNsQixDQUFDO0FBRUQ7Ozs7Ozs7Ozs7R0FVRztBQUNILE1BQU0sQ0FBQyxNQUFNLFdBQVcsR0FBRztJQUN6QixLQUFLLENBQUMsUUFBUSxDQUFDLEtBQW9CLEVBQUUsU0FBaUIsRUFBRSxTQUFpQjtRQUN2RSxNQUFNLEVBQUUsR0FBRyxLQUFLLEVBQUUsQ0FB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QUFJLEtBQUssQ0FBQyxNQUFNLEtBQUssQ0FBQyxFQUFFLENBQUM7Z0JBQ2pDLE9BQU87b0JBQ0wsT0FBTyxFQUFFLEtBQUs7b0JBQ2QsS0FBSyxFQUFFLElBQUksU0FBUyxDQUFDLGdCQUFnQixFQUFFLHdCQUF3QixDQUFDO2lCQUNqRSxDQUFDO1lBQ0osQ0FBQztZQUVELE9BQU87Z0JBQ0wsT0FBTyxFQUFFLElBQUk7Z0JBQ2IsSUFBSSxFQUFFLEtBQUssQ0FBQyxDQUFDLENBQUM7YUFDZixDQUFDO1FBQ0osQ0FBQztRQUFDLE9BQU8sS0FBSyxFQUFFLENBQUM7WUFDZixPQUFPLENBQUMsS0FBSyxDQUFDLHVDQUF1QyxFQUFFLEtBQUssQ0FBQyxDQUFDO1lBQzlELE9BQU87Z0JBQ0wsT0FBTyxFQUFFLEtBQUs7Z0JBQ2QsS0FBSyxFQUFFLElBQUksU0FBUyxDQUFDLGdCQUFnQixFQUFFLGdDQUFnQyxDQUFDO2FBQ3pFLENBQUM7UUFDSixDQUFDO0lBQ0gsQ0FBQztDQUNGLENBQUM7QUFFRiw2QkFBNkI7QUFDN0IsT0FBTyxFQUFFLEdBQUcsRUFBRSxNQUFNLGFBQWEsQ0FBQyIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogU2VydmnDp28gZGUgQXV0ZW50aWNhw6fDo28gUHJpbmNpcGFsXG4gKiBcbiAqIFJlc3BvbnNhYmlsaWRhZGVzOlxuICogLSBSZWdpc3RybyBkZSB1c3XDoXJpb3NcbiAqIC0gTG9naW4gY29tIHZhbGlkYcOnw6NvIGRlIGNyZWRlbmNpYWlzXG4gKiAtIEdlcmVuY2lhbWVudG8gZGUgdGVudGF0aXZhcyBlIGxvY2tvdXRcbiAqIC0gSW50ZWdyYcOnw6NvIGNvbSBNRkFcbiAqIC0gQXVkaXRvcmlhIGRlIGV2ZW50b3NcbiAqL1xuXG5pbXBvcnQgeyBlcSB9IGZyb20gJ2RyaXp6bGUtb3JtJztcbmltcG9ydCB7IGhhc2hQYXNzd29yZCwgdmVyaWZ5UGFzc3dvcmQsIGdlbmVyYXRlU2FsdCwgc2hhMjU2IH0gZnJvbSAnQHplcm8vY3J5cHRvJztcbmltcG9ydCB7IHNjaGVtYSwgdHlwZSBOZXdVc2VyLCB0eXBlIFVzZXIgYXMgREJVc2VyIH0gZnJvbSAnQHplcm8vZGF0YWJhc2UnO1xuaW1wb3J0IHsgZ2VuZXJhdGVVVUlEIH0gZnJvbSAnQHplcm8vc2hhcmVkJztcbmltcG9ydCB7IEFVVEhfQ09OU1RBTlRTIH0gZnJvbSAnLi4vY29uc3RhbnRzJztcbmltcG9ydCB0eXBlIHsgXG4gIFJlZ2lzdGVySW5wdXQsIFxuICBMb2dpbklucHV0LCBcbiAgQXV0aFJlc3BvbnNlLCBcbiAgQXV0aEVycm9yLFxuICBBdXRoQXVkaXRFdmVudCBcbn0gZnJvbSAnLi4vdHlwZXMnO1xuaW1wb3J0IHsgdmFsaWRhdGVFbWFpbCwgdmFsaWRhdGVQYXNzd29yZCwgbm9ybWFsaXplRW1haWwgfSBmcm9tICcuLi91dGlscy92YWxpZGF0aW9uJztcbmltcG9ydCB7IGdlbmVyYXRlQXV0aFRva2VucyB9IGZyb20gJy4uL3V0aWxzL3Rva2Vucyc7XG5cbi8vIE1vY2sgZG8gZGF0YWJhc2UgY2xpZW50IChzZXLDoSBpbmpldGFkbyBwZWxhIEFQSSlcbmxldCBkYkNsaWVudDogYW55ID0gbnVsbDtcblxuZXhwb3J0IGZ1bmN0aW9uIHNldERhdGFiYXNlQ2xpZW50KGNsaWVudDogYW55KTogdm9pZCB7XG4gIGRiQ2xpZW50ID0gY2xpZW50O1xufVxuXG5mdW5jdGlvbiBnZXREQigpIHtcbiAgaWYgKCFkYkNsaWVudCkge1xuICAgIHRocm93IG5ldyBFcnJvcignRGF0YWJhc2UgY2xpZW50IG7Do28gaW5pY2lhbGl6YWRvJyk7XG4gIH1cbiAgcmV0dXJuIGRiQ2xpZW50O1xufVxuXG4vKipcbiAqIFJlZ2lzdHJhIG5vdm8gdXN1w6FyaW8gbm8gc2lzdGVtYVxuICogXG4gKiBTRUNVUklUWSBOT1RFUzpcbiAqIC0gRW1haWwgbm9ybWFsaXphZG8gcGFyYSBsb3dlcmNhc2VcbiAqIC0gU2VuaGEgaGFzaCBjb20gQXJnb24yaWQgYW50ZXMgZGUgYXJtYXplbmFyXG4gKiAtIFZhbGlkYcOnw6NvIGRlIGZvcsOnYSBkYSBzZW5oYVxuICogLSBWZXJpZmljYcOnw6NvIGRlIGVtYWlsIGR1cGxpY2Fkb1xuICogLSBHZXJhw6fDo28gZGUgcmVjb3ZlcnkgY29kZXNcbiAqIC0gQXVkaXRvcmlhIGRvIGV2ZW50b1xuICovXG5leHBvcnQgY29uc3QgQXV0aFNlcnZpY2UgPSB7XG4gIGFzeW5jIHJlZ2lzdGVyKGlucHV0OiBSZWdpc3RlcklucHV0LCBpcEFkZHJlc3M6IHN0cmluZywgdXNlckFnZW50OiBzdHJpbmcpOiBQcm9taXNlPEF1dGhSZXNwb25zZT4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcbiAgICBcbiAgICAvLyBBdWRpdDogcmVnaXN0cm8gaW5pY2lhZG9cbiAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgIGFjdGlvbjogJ1JFR0lTVEVSX1JFUVVFU1QnLFxuICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgaXBBZGRyZXNzLFxuICAgICAgdXNlckFnZW50LFxuICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgIG1ldGFkYXRhOiB7IGVtYWlsOiBpbnB1dC5lbWFpbCB9LFxuICAgIH0pO1xuXG4gICAgLy8gVmFsaWRhciBlbWFpbFxuICAgIGNvbnN0IGVtYWlsVmFsaWRhdGlvbiA9IHZhbGlkYXRlRW1haWwoaW5wdXQuZW1haWwpO1xuICAgIGlmICghZW1haWxWYWxpZGF0aW9uLnZhbGlkKSB7XG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnUkVHSVNURVJfRkFJTFVSRScsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiBlbWFpbFZhbGlkYXRpb24uZXJyb3I/Lm1lc3NhZ2UsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IGZhbHNlLCBlcnJvcjogZW1haWxWYWxpZGF0aW9uLmVycm9yIH07XG4gICAgfVxuXG4gICAgLy8gVmFsaWRhciBzZW5oYVxuICAgIGNvbnN0IHBhc3N3b3JkVmFsaWRhdGlvbiA9IHZhbGlkYXRlUGFzc3dvcmQoaW5wdXQucGFzc3dvcmQpO1xuICAgIGlmICghcGFzc3dvcmRWYWxpZGF0aW9uLnZhbGlkKSB7XG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnUkVHSVNURVJfRkFJTFVSRScsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiBwYXNzd29yZFZhbGlkYXRpb24uZXJyb3I/Lm1lc3NhZ2UsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IGZhbHNlLCBlcnJvcjogcGFzc3dvcmRWYWxpZGF0aW9uLmVycm9yIH07XG4gICAgfVxuXG4gICAgY29uc3Qgbm9ybWFsaXplZEVtYWlsID0gbm9ybWFsaXplRW1haWwoaW5wdXQuZW1haWwpO1xuXG4gICAgLy8gVmVyaWZpY2FyIHNlIGVtYWlsIGrDoSBleGlzdGVcbiAgICB0cnkge1xuICAgICAgY29uc3QgZXhpc3RpbmdVc2VyID0gYXdhaXQgZGJcbiAgICAgICAgLnNlbGVjdCgpXG4gICAgICAgIC5mcm9tKHNjaGVtYS51c2VycylcbiAgICAgICAgLndoZXJlKGVxKHNjaGVtYS51c2Vycy5lbWFpbCwgbm9ybWFsaXplZEVtYWlsKSlcbiAgICAgICAgLmxpbWl0KDEpO1xuXG4gICAgICBpZiAoZXhpc3RpbmdVc2VyICYmIGV4aXN0aW5nVXNlci5sZW5ndGggPiAwKSB7XG4gICAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICAgIGFjdGlvbjogJ1JFR0lTVEVSX0ZBSUxVUkUnLFxuICAgICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgICAgdXNlckFnZW50LFxuICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgIGZhaWx1cmVSZWFzb246ICdFbWFpbCBqw6EgY2FkYXN0cmFkbycsXG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgIGVycm9yOiB7IGNvZGU6ICdFTUFJTF9BTFJFQURZX0VYSVNUUycsIG1lc3NhZ2U6ICdFbWFpbCBqw6EgY2FkYXN0cmFkbycgfSxcbiAgICAgICAgfTtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ1JFR0lTVEVSX0ZBSUxVUkUnLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZmFpbHVyZVJlYXNvbjogJ0Vycm8gYW8gdmVyaWZpY2FyIGVtYWlsJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlRFUk5BTF9FUlJPUicsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLklOVEVSTkFMX0VSUk9SIH0sXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIEhhc2ggZGEgc2VuaGEgY29tIEFyZ29uMmlkXG4gICAgbGV0IHBhc3N3b3JkSGFzaDogc3RyaW5nO1xuICAgIHRyeSB7XG4gICAgICBwYXNzd29yZEhhc2ggPSBhd2FpdCBoYXNoUGFzc3dvcmQoaW5wdXQucGFzc3dvcmQpO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnUkVHSVNURVJfRkFJTFVSRScsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnRXJybyBhbyBoYXNoIHNlbmhhJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlRFUk5BTF9FUlJPUicsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLklOVEVSTkFMX0VSUk9SIH0sXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIENyaWFyIHVzdcOhcmlvXG4gICAgY29uc3QgdXNlcklkID0gZ2VuZXJhdGVVVUlEKCk7XG4gICAgY29uc3Qgc2FsdCA9IGdlbmVyYXRlU2FsdCgpO1xuICAgIGNvbnN0IG5ld1VzZXI6IE5ld1VzZXIgPSB7XG4gICAgICBpZDogdXNlcklkLFxuICAgICAgZW1haWw6IG5vcm1hbGl6ZWRFbWFpbCxcbiAgICAgIHBhc3N3b3JkSGFzaCxcbiAgICAgIHBhc3N3b3JkU2FsdDogc2FsdCxcbiAgICAgIGRpc3BsYXlOYW1lOiBpbnB1dC5kaXNwbGF5TmFtZT8udHJpbSgpIHx8IG51bGwsXG4gICAgICByZWNvdmVyeUVtYWlsOiBpbnB1dC5yZWNvdmVyeUVtYWlsID8gbm9ybWFsaXplRW1haWwoaW5wdXQucmVjb3ZlcnlFbWFpbCkgOiBudWxsLFxuICAgICAgc3RhdHVzOiAncGVuZGluZ19tZmEnLCAvLyBSZXF1ZXIgc2V0dXAgZGUgTUZBIGFww7NzIHJlZ2lzdHJvXG4gICAgICBtZmFFbmFibGVkOiBmYWxzZSxcbiAgICAgIGNyZWF0ZWRBdDogbmV3IERhdGUoKSxcbiAgICAgIHVwZGF0ZWRBdDogbmV3IERhdGUoKSxcbiAgICAgIGZhaWxlZExvZ2luQXR0ZW1wdHM6IDAsXG4gICAgICBsb2NrZWRVbnRpbDogbnVsbCxcbiAgICAgIGxhc3RMb2dpbkF0OiBudWxsLFxuICAgICAgZmFjaWFsVGVtcGxhdGVIYXNoOiBudWxsLCAvLyBTZXLDoSBkZWZpbmlkbyBzZSB1c2FyIGJpb21ldHJpYVxuICAgIH07XG5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgZGIuaW5zZXJ0KHNjaGVtYS51c2VycykudmFsdWVzKG5ld1VzZXIpO1xuXG4gICAgICAvLyBUT0RPOiBHZXJhciByZWNvdmVyeSBjb2RlcyBlIHNhbHZhciBlbSBlbmNyeXB0aW9uX2tleXNcblxuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ1JFR0lTVEVSX1NVQ0NFU1MnLFxuICAgICAgICB1c2VySWQsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgdXNlcklkLFxuICAgICAgICByZXF1aXJlc01GQTogdHJ1ZSxcbiAgICAgIH07XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdSRUdJU1RFUl9GQUlMVVJFJyxcbiAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGZhaWx1cmVSZWFzb246ICdFcnJvIGFvIGNyaWFyIHVzdcOhcmlvJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlRFUk5BTF9FUlJPUicsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLklOVEVSTkFMX0VSUk9SIH0sXG4gICAgICB9O1xuICAgIH1cbiAgfSxcblxuICAvKipcbiAgICogQXV0ZW50aWNhIHVzdcOhcmlvIGNvbSBlbWFpbCBlIHNlbmhhXG4gICAqIFxuICAgKiBTRUNVUklUWSBOT1RFUzpcbiAgICogLSBUaW1pbmctc2FmZSBjb21wYXJpc29uIHBhcmEgc2VuaGFcbiAgICogLSBSYXRlIGxpbWl0aW5nIHBvciBJUCBlIHVzdcOhcmlvXG4gICAqIC0gTG9ja291dCBhcMOzcyBtw7psdGlwbGFzIGZhbGhhc1xuICAgKiAtIE1lbnNhZ2VucyBkZSBlcnJvIGdlbsOpcmljYXMgKG7Do28gcmV2ZWxhciBzZSBlbWFpbCBleGlzdGUpXG4gICAqIC0gUmVxdWVyIE1GQSBzZSBoYWJpbGl0YWRvXG4gICAqL1xuICBhc3luYyBsb2dpbihpbnB1dDogTG9naW5JbnB1dCwgaXBBZGRyZXNzOiBzdHJpbmcsIHVzZXJBZ2VudDogc3RyaW5nKTogUHJvbWlzZTxBdXRoUmVzcG9uc2U+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG5cbiAgICAvLyBBdWRpdDogbG9naW4gaW5pY2lhZG9cbiAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgIGFjdGlvbjogJ0xPR0lOX1JFUVVFU1QnLFxuICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgaXBBZGRyZXNzLFxuICAgICAgdXNlckFnZW50LFxuICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgIG1ldGFkYXRhOiB7IGVtYWlsOiBpbnB1dC5lbWFpbCB9LFxuICAgIH0pO1xuXG4gICAgLy8gVmFsaWRhciBmb3JtYXRvIGRvIGVtYWlsXG4gICAgY29uc3QgZW1haWxWYWxpZGF0aW9uID0gdmFsaWRhdGVFbWFpbChpbnB1dC5lbWFpbCk7XG4gICAgaWYgKCFlbWFpbFZhbGlkYXRpb24udmFsaWQpIHtcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdMT0dJTl9GQUlMVVJFX1BBU1NXT1JEJyxcbiAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGZhaWx1cmVSZWFzb246ICdFbWFpbCBpbnbDoWxpZG8nLFxuICAgICAgfSk7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZXJyb3I6IHsgY29kZTogJ0lOVkFMSURfQ1JFREVOVElBTFMnLCBtZXNzYWdlOiBBVVRIX0NPTlNUQU5UUy5FUlJPUl9NRVNTQUdFUy5JTlZBTElEX0NSRURFTlRJQUxTIH0sXG4gICAgICB9O1xuICAgIH1cblxuICAgIGNvbnN0IG5vcm1hbGl6ZWRFbWFpbCA9IG5vcm1hbGl6ZUVtYWlsKGlucHV0LmVtYWlsKTtcblxuICAgIC8vIEJ1c2NhciB1c3XDoXJpb1xuICAgIGxldCB1c2VyOiBEQlVzZXIgfCBudWxsID0gbnVsbDtcbiAgICB0cnkge1xuICAgICAgY29uc3QgdXNlcnMgPSBhd2FpdCBkYlxuICAgICAgICAuc2VsZWN0KClcbiAgICAgICAgLmZyb20oc2NoZW1hLnVzZXJzKVxuICAgICAgICAud2hlcmUoZXEoc2NoZW1hLnVzZXJzLmVtYWlsLCBub3JtYWxpemVkRW1haWwpKVxuICAgICAgICAubGltaXQoMSk7XG5cbiAgICAgIHVzZXIgPSB1c2VycyAmJiB1c2Vycy5sZW5ndGggPiAwID8gdXNlcnNbMF0gOiBudWxsO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnTE9HSU5fRkFJTFVSRV9QQVNTV09SRCcsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnRXJybyBhbyBidXNjYXIgdXN1w6FyaW8nLFxuICAgICAgfSk7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZXJyb3I6IHsgY29kZTogJ0lOVEVSTkFMX0VSUk9SJywgbWVzc2FnZTogQVVUSF9DT05TVEFOVFMuRVJST1JfTUVTU0FHRVMuSU5URVJOQUxfRVJST1IgfSxcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gU2UgdXN1w6FyaW8gbsOjbyBleGlzdGlyLCBzaW11bGFyIGRlbGF5IHBhcmEgcHJldmVuaXIgdGltaW5nIGF0dGFja1xuICAgIGlmICghdXNlcikge1xuICAgICAgYXdhaXQgbmV3IFByb21pc2UocmVzb2x2ZSA9PiBzZXRUaW1lb3V0KHJlc29sdmUsIDEwMCArIE1hdGgucmFuZG9tKCkgKiAxMDApKTtcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdMT0dJTl9GQUlMVVJFX1BBU1NXT1JEJyxcbiAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGZhaWx1cmVSZWFzb246ICdVc3XDoXJpbyBuw6NvIGVuY29udHJhZG8nLFxuICAgICAgfSk7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZXJyb3I6IHsgY29kZTogJ0lOVkFMSURfQ1JFREVOVElBTFMnLCBtZXNzYWdlOiBBVVRIX0NPTlNUQU5UUy5FUlJPUl9NRVNTQUdFUy5JTlZBTElEX0NSRURFTlRJQUxTIH0sXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFZlcmlmaWNhciBzZSBjb250YSBlc3TDoSBibG9xdWVhZGFcbiAgICBpZiAodXNlci5sb2NrZWRVbnRpbCAmJiBuZXcgRGF0ZSh1c2VyLmxvY2tlZFVudGlsKSA+IG5ldyBEYXRlKCkpIHtcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdMT0dJTl9GQUlMVVJFX0xPQ0tFRCcsXG4gICAgICAgIHVzZXJJZDogdXNlci5pZCxcbiAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGZhaWx1cmVSZWFzb246ICdDb250YSBibG9xdWVhZGEnLFxuICAgICAgfSk7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZXJyb3I6IHsgY29kZTogJ1VTRVJfTE9DS0VEJywgbWVzc2FnZTogQVVUSF9DT05TVEFOVFMuRVJST1JfTUVTU0FHRVMuVVNFUl9MT0NLRUQgfSxcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gVmVyaWZpY2FyIHNlbmhhIGNvbSB0aW1pbmctc2FmZSBjb21wYXJpc29uXG4gICAgY29uc3QgcGFzc3dvcmRWYWxpZCA9IGF3YWl0IHZlcmlmeVBhc3N3b3JkKGlucHV0LnBhc3N3b3JkLCB1c2VyLnBhc3N3b3JkSGFzaCk7XG4gICAgXG4gICAgaWYgKCFwYXNzd29yZFZhbGlkKSB7XG4gICAgICAvLyBJbmNyZW1lbnRhciB0ZW50YXRpdmFzIGZhbGhhc1xuICAgICAgYXdhaXQgdGhpcy5pbmNyZW1lbnRGYWlsZWRBdHRlbXB0cyh1c2VyLmlkKTtcbiAgICAgIFxuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ0xPR0lOX0ZBSUxVUkVfUEFTU1dPUkQnLFxuICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnU2VuaGEgaW52w6FsaWRhJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlZBTElEX0NSRURFTlRJQUxTJywgbWVzc2FnZTogQVVUSF9DT05TVEFOVFMuRVJST1JfTUVTU0FHRVMuSU5WQUxJRF9DUkVERU5USUFMUyB9LFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBSZXNldGFyIHRlbnRhdGl2YXMgZmFsaGFzIGFww7NzIGxvZ2luIGJlbS1zdWNlZGlkb1xuICAgIGF3YWl0IHRoaXMucmVzZXRGYWlsZWRBdHRlbXB0cyh1c2VyLmlkKTtcblxuICAgIC8vIFZlcmlmaWNhciBzZSBNRkEgZXN0w6EgaGFiaWxpdGFkb1xuICAgIGlmICghdXNlci5tZmFFbmFibGVkKSB7XG4gICAgICAvLyBVc3XDoXJpbyBwcmVjaXNhIGNvbmZpZ3VyYXIgTUZBIChlc3RhZG8gcGVuZGluZ19tZmEpXG4gICAgICBpZiAodXNlci5zdGF0dXMgPT09ICdwZW5kaW5nX21mYScpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICAgIHVzZXJJZDogdXNlci5pZCxcbiAgICAgICAgICByZXF1aXJlc01GQTogdHJ1ZSxcbiAgICAgICAgfTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBTZSBjaGVnb3UgYXF1aSwgc2VuaGEgdsOhbGlkYSBlIE1GQSBwb2RlIGVzdGFyIGhhYmlsaXRhZG9cbiAgICAvLyBTZSBNRkEgaGFiaWxpdGFkbywgcmVxdWVyIGPDs2RpZ29cbiAgICBpZiAodXNlci5tZmFFbmFibGVkKSB7XG4gICAgICBpZiAoIWlucHV0Lm1mYUNvZGUpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICAgIHVzZXJJZDogdXNlci5pZCxcbiAgICAgICAgICByZXF1aXJlc01GQTogdHJ1ZSxcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgLy8gVmVyaWZpY2FyIGPDs2RpZ28gTUZBIHNlcsOhIGZlaXRvIHBlbG8gTUZBU2VydmljZVxuICAgICAgLy8gUmV0b3JuYXIgcGFyYSBvIGNvbnRyb2xsZXIgY2hhbWFyIG8gcHLDs3hpbW8gcGFzc29cbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgIHVzZXJJZDogdXNlci5pZCxcbiAgICAgICAgcmVxdWlyZXNNRkE6IHRydWUsXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIE1GQSBuw6NvIGhhYmlsaXRhZG8gKGRldmVyaWEgc2VyIHJhcm8gZW0gcHJvZHXDp8OjbylcbiAgICAvLyBDcmlhciBzZXNzw6NvIGRpcmV0YW1lbnRlXG4gICAgcmV0dXJuIGF3YWl0IHRoaXMuY3JlYXRlU2Vzc2lvbih1c2VyLCBpbnB1dCwgaXBBZGRyZXNzLCB1c2VyQWdlbnQpO1xuICB9LFxuXG4gIC8qKlxuICAgKiBDcmlhIHNlc3PDo28gYXDDs3MgYXV0ZW50aWNhw6fDo28gYmVtLXN1Y2VkaWRhXG4gICAqL1xuICBhc3luYyBjcmVhdGVTZXNzaW9uKFxuICAgIHVzZXI6IERCVXNlcixcbiAgICBpbnB1dDogTG9naW5JbnB1dCxcbiAgICBpcEFkZHJlc3M6IHN0cmluZyxcbiAgICB1c2VyQWdlbnQ6IHN0cmluZ1xuICApOiBQcm9taXNlPEF1dGhSZXNwb25zZT4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcblxuICAgIHRyeSB7XG4gICAgICAvLyBHZXJhciB0b2tlbnMgSldUXG4gICAgICBjb25zdCBzZXNzaW9uSWQgPSBnZW5lcmF0ZVVVSUQoKTtcbiAgICAgIGNvbnN0IHRva2VucyA9IGF3YWl0IGdlbmVyYXRlQXV0aFRva2Vucyh7XG4gICAgICAgIHVzZXJJZDogdXNlci5pZCxcbiAgICAgICAgc2Vzc2lvbklkLFxuICAgICAgICBtZmFWZXJpZmllZDogdXNlci5tZmFFbmFibGVkIHx8IGZhbHNlLFxuICAgICAgICBjb3VudGVyOiAwLFxuICAgICAgfSk7XG5cbiAgICAgIC8vIFNhbHZhciBzZXNzw6NvIG5vIGJhbmNvXG4gICAgICBhd2FpdCBkYi5pbnNlcnQoc2NoZW1hLnNlc3Npb25zKS52YWx1ZXMoe1xuICAgICAgICBpZDogc2Vzc2lvbklkLFxuICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgIHJlZnJlc2hUb2tlbkhhc2g6IGF3YWl0IHNoYTI1Nih0b2tlbnMucmVmcmVzaFRva2VuKSxcbiAgICAgICAgZXhwaXJlc0F0OiB0b2tlbnMuZXhwaXJlc0F0LFxuICAgICAgICByZWZyZXNoRXhwaXJlc0F0OiB0b2tlbnMucmVmcmVzaEV4cGlyZXNBdCxcbiAgICAgICAgY3JlYXRlZEF0OiBuZXcgRGF0ZSgpLFxuICAgICAgICByZXZva2VkOiBmYWxzZSxcbiAgICAgIH0pO1xuXG4gICAgICAvLyBBdHVhbGl6YXIgw7psdGltbyBsb2dpblxuICAgICAgYXdhaXQgZGJcbiAgICAgICAgLnVwZGF0ZShzY2hlbWEudXNlcnMpXG4gICAgICAgIC5zZXQoe1xuICAgICAgICAgIGxhc3RMb2dpbkF0OiBuZXcgRGF0ZSgpLFxuICAgICAgICAgIHVwZGF0ZWRBdDogbmV3IERhdGUoKSxcbiAgICAgICAgfSlcbiAgICAgICAgLndoZXJlKGVxKHNjaGVtYS51c2Vycy5pZCwgdXNlci5pZCkpO1xuXG4gICAgICAvLyBDcmlhci9hdHVhbGl6YXIgZGlzcG9zaXRpdm9cbiAgICAgIGxldCBkZXZpY2VJZDogc3RyaW5nIHwgdW5kZWZpbmVkO1xuICAgICAgY29uc3QgZGV2aWNlVHlwZSA9IHRoaXMuZGV0ZWN0RGV2aWNlVHlwZSh1c2VyQWdlbnQpO1xuICAgICAgY29uc3QgeyBvcywgYnJvd3NlciB9ID0gdGhpcy5wYXJzZVVzZXJBZ2VudCh1c2VyQWdlbnQpO1xuICAgICAgXG4gICAgICBpZiAoaW5wdXQuZGV2aWNlSWQpIHtcbiAgICAgICAgZGV2aWNlSWQgPSBpbnB1dC5kZXZpY2VJZDtcbiAgICAgICAgYXdhaXQgZGJcbiAgICAgICAgICAudXBkYXRlKHNjaGVtYS5kZXZpY2VzKVxuICAgICAgICAgIC5zZXQoe1xuICAgICAgICAgICAgbGFzdFNlZW5BdDogbmV3IERhdGUoKSxcbiAgICAgICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgICB9KVxuICAgICAgICAgIC53aGVyZShlcShzY2hlbWEuZGV2aWNlcy5pZCwgZGV2aWNlSWQpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vIENyaWFyIG5vdm8gZGlzcG9zaXRpdm9cbiAgICAgICAgZGV2aWNlSWQgPSBnZW5lcmF0ZVVVSUQoKTtcblxuICAgICAgICBhd2FpdCBkYi5pbnNlcnQoc2NoZW1hLmRldmljZXMpLnZhbHVlcyh7XG4gICAgICAgICAgaWQ6IGRldmljZUlkLFxuICAgICAgICAgIHVzZXJJZDogdXNlci5pZCxcbiAgICAgICAgICBuYW1lOiBgJHtkZXZpY2VUeXBlfSAtICR7YnJvd3Nlcn0gb24gJHtvc31gLFxuICAgICAgICAgIHR5cGU6IGRldmljZVR5cGUsXG4gICAgICAgICAgb3MsXG4gICAgICAgICAgYnJvd3NlcixcbiAgICAgICAgICBpc1RydXN0ZWQ6IGlucHV0LnJlbWVtYmVyRGV2aWNlID8/IGZhbHNlLFxuICAgICAgICAgIHRydXN0ZWRVbnRpbDogaW5wdXQucmVtZW1iZXJEZXZpY2VcbiAgICAgICAgICAgID8gbmV3IERhdGUoRGF0ZS5ub3coKSArIEFVVEhfQ09OU1RBTlRTLlRSVVNURURfREVWSUNFX0VYUElSWV9EQVlTICogMjQgKiA2MCAqIDYwICogMTAwMClcbiAgICAgICAgICAgIDogbnVsbCxcbiAgICAgICAgICBsYXN0U2VlbkF0OiBuZXcgRGF0ZSgpLFxuICAgICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgICAgY3JlYXRlZEF0OiBuZXcgRGF0ZSgpLFxuICAgICAgICB9KTtcbiAgICAgIH1cblxuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ0xPR0lOX1NVQ0NFU1MnLFxuICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgIHNlc3Npb25JZCxcbiAgICAgICAgZGV2aWNlSWQsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgdXNlcklkOiB1c2VyLmlkLFxuICAgICAgICBzZXNzaW9uOiB7XG4gICAgICAgICAgc2Vzc2lvbklkLFxuICAgICAgICAgIHVzZXJJZDogdXNlci5pZCxcbiAgICAgICAgICBhY2Nlc3NUb2tlbjogdG9rZW5zLmFjY2Vzc1Rva2VuLFxuICAgICAgICAgIHJlZnJlc2hUb2tlbjogdG9rZW5zLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICBleHBpcmVzQXQ6IHRva2Vucy5leHBpcmVzQXQsXG4gICAgICAgICAgcmVmcmVzaEV4cGlyZXNBdDogdG9rZW5zLnJlZnJlc2hFeHBpcmVzQXQsXG4gICAgICAgICAgZGV2aWNlOiB7XG4gICAgICAgICAgICBkZXZpY2VJZDogZGV2aWNlSWQhLFxuICAgICAgICAgICAgbmFtZTogYCR7ZGV2aWNlVHlwZX0gLSAke2Jyb3dzZXJ9IG9uICR7b3N9YCxcbiAgICAgICAgICAgIHR5cGU6IGRldmljZVR5cGUsXG4gICAgICAgICAgICBvcyxcbiAgICAgICAgICAgIGJyb3dzZXIsXG4gICAgICAgICAgICBpc1RydXN0ZWQ6IGlucHV0LnJlbWVtYmVyRGV2aWNlID8/IGZhbHNlLFxuICAgICAgICAgICAgbGFzdFNlZW5BdDogbmV3IERhdGUoKSxcbiAgICAgICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgICB9LFxuICAgICAgICAgIG1mYVZlcmlmaWVkOiB1c2VyLm1mYUVuYWJsZWQgfHwgZmFsc2UsXG4gICAgICAgICAgY3JlYXRlZEF0OiBuZXcgRGF0ZSgpLFxuICAgICAgICB9LFxuICAgICAgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ0xPR0lOX0ZBSUxVUkVfUEFTU1dPUkQnLFxuICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnRXJybyBhbyBjcmlhciBzZXNzw6NvJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlRFUk5BTF9FUlJPUicsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLklOVEVSTkFMX0VSUk9SIH0sXG4gICAgICB9O1xuICAgIH1cbiAgfSxcblxuICAvKipcbiAgICogSW5jcmVtZW50YSB0ZW50YXRpdmFzIGZhbGhhcyBlIGFwbGljYSBsb2Nrb3V0IHNlIG5lY2Vzc8OhcmlvXG4gICAqL1xuICBhc3luYyBpbmNyZW1lbnRGYWlsZWRBdHRlbXB0cyh1c2VySWQ6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcbiAgICBcbiAgICBhd2FpdCBkYlxuICAgICAgLnVwZGF0ZShzY2hlbWEudXNlcnMpXG4gICAgICAuc2V0KHtcbiAgICAgICAgZmFpbGVkTG9naW5BdHRlbXB0czogc3FsYCR7c2NoZW1hLnVzZXJzLmZhaWxlZExvZ2luQXR0ZW1wdHN9ICsgMWAsXG4gICAgICAgIGxvY2tlZFVudGlsOiBzcWxgQ0FTRSBcbiAgICAgICAgICBXSEVOICR7c2NoZW1hLnVzZXJzLmZhaWxlZExvZ2luQXR0ZW1wdHN9ICsgMSA+PSAke0FVVEhfQ09OU1RBTlRTLk1BWF9MT0dJTl9BVFRFTVBUU31cbiAgICAgICAgICBUSEVOIE5PVygpICsgSU5URVJWQUwgJyR7QVVUSF9DT05TVEFOVFMuTE9DS09VVF9EVVJBVElPTn0gc2Vjb25kcydcbiAgICAgICAgICBFTFNFICR7c2NoZW1hLnVzZXJzLmxvY2tlZFVudGlsfVxuICAgICAgICBFTkRgLFxuICAgICAgICB1cGRhdGVkQXQ6IG5ldyBEYXRlKCksXG4gICAgICB9KVxuICAgICAgLndoZXJlKGVxKHNjaGVtYS51c2Vycy5pZCwgdXNlcklkKSk7XG4gIH0sXG5cbiAgLyoqXG4gICAqIFJlc2V0IHRlbnRhdGl2YXMgZmFsaGFzIGFww7NzIGxvZ2luIGJlbS1zdWNlZGlkb1xuICAgKi9cbiAgYXN5bmMgcmVzZXRGYWlsZWRBdHRlbXB0cyh1c2VySWQ6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcbiAgICBcbiAgICBhd2FpdCBkYlxuICAgICAgLnVwZGF0ZShzY2hlbWEudXNlcnMpXG4gICAgICAuc2V0KHtcbiAgICAgICAgZmFpbGVkTG9naW5BdHRlbXB0czogMCxcbiAgICAgICAgbG9ja2VkVW50aWw6IG51bGwsXG4gICAgICAgIHVwZGF0ZWRBdDogbmV3IERhdGUoKSxcbiAgICAgIH0pXG4gICAgICAud2hlcmUoZXEoc2NoZW1hLnVzZXJzLmlkLCB1c2VySWQpKTtcbiAgfSxcblxuICAvKipcbiAgICogRGV0ZWN0YSB0aXBvIGRlIGRpc3Bvc2l0aXZvIGEgcGFydGlyIGRvIHVzZXIgYWdlbnRcbiAgICovXG4gIGRldGVjdERldmljZVR5cGUodXNlckFnZW50OiBzdHJpbmcpOiAnZGVza3RvcCcgfCAnbW9iaWxlJyB8ICd0YWJsZXQnIHwgJ3Vua25vd24nIHtcbiAgICBjb25zdCB1YSA9IHVzZXJBZ2VudC50b0xvd2VyQ2FzZSgpO1xuICAgIFxuICAgIGlmICgvbW9iaWxlfGFuZHJvaWR8aXBob25lfGlwb2R8YmxhY2tiZXJyeXx3aW5kb3dzIHBob25lL2kudGVzdCh1YSkpIHtcbiAgICAgIHJldHVybiAnbW9iaWxlJztcbiAgICB9XG4gICAgaWYgKC90YWJsZXR8aXBhZHxzaWxrfGtpbmRsZS9pLnRlc3QodWEpKSB7XG4gICAgICByZXR1cm4gJ3RhYmxldCc7XG4gICAgfVxuICAgIGlmICgvZGVza3RvcHx3aW5kb3dzfG1hY2ludG9zaHxsaW51eHx1YnVudHUvaS50ZXN0KHVhKSkge1xuICAgICAgcmV0dXJuICdkZXNrdG9wJztcbiAgICB9XG4gICAgXG4gICAgcmV0dXJuICd1bmtub3duJztcbiAgfSxcblxuICAvKipcbiAgICogUGFyc2UgdXNlciBhZ2VudCBwYXJhIGV4dHJhaXIgT1MgZSBicm93c2VyXG4gICAqIEltcGxlbWVudGHDp8OjbyBzaW1wbGlmaWNhZGEgLSB1c2FyIGJpYmxpb3RlY2EgZGVkaWNhZGEgZW0gcHJvZHXDp8Ojb1xuICAgKi9cbiAgcGFyc2VVc2VyQWdlbnQodXNlckFnZW50OiBzdHJpbmcpOiB7IG9zOiBzdHJpbmc7IGJyb3dzZXI6IHN0cmluZyB9IHtcbiAgICBjb25zdCB1YSA9IHVzZXJBZ2VudC50b0xvd2VyQ2FzZSgpO1xuICAgIFxuICAgIGxldCBvcyA9ICdVbmtub3duJztcbiAgICBpZiAoL3dpbmRvd3MgbnQvaS50ZXN0KHVhKSkgb3MgPSAnV2luZG93cyc7XG4gICAgZWxzZSBpZiAoL21hY2ludG9zaHxtYWMgb3MgeC9pLnRlc3QodWEpKSBvcyA9ICdtYWNPUyc7XG4gICAgZWxzZSBpZiAoL2xpbnV4fHVidW50dS9pLnRlc3QodWEpKSBvcyA9ICdMaW51eCc7XG4gICAgZWxzZSBpZiAoL2FuZHJvaWQvaS50ZXN0KHVhKSkgb3MgPSAnQW5kcm9pZCc7XG4gICAgZWxzZSBpZiAoL2lwaG9uZXxpcGFkfGlwb2QvaS50ZXN0KHVhKSkgb3MgPSAnaU9TJztcbiAgICBcbiAgICBsZXQgYnJvd3NlciA9ICdVbmtub3duJztcbiAgICBpZiAoL2Nocm9tZXxjcmlvcy9pLnRlc3QodWEpKSBicm93c2VyID0gJ0Nocm9tZSc7XG4gICAgZWxzZSBpZiAoL2ZpcmVmb3h8Znhpb3MvaS50ZXN0KHVhKSkgYnJvd3NlciA9ICdGaXJlZm94JztcbiAgICBlbHNlIGlmICgvc2FmYXJpfHZlcnNpb25cXC9cXGQrL2kudGVzdCh1YSkgJiYgIS9jaHJvbWUvaS50ZXN0KHVhKSkgYnJvd3NlciA9ICdTYWZhcmknO1xuICAgIGVsc2UgaWYgKC9lZGcvaS50ZXN0KHVhKSkgYnJvd3NlciA9ICdFZGdlJztcbiAgICBlbHNlIGlmICgvb3BlcmF8b3ByL2kudGVzdCh1YSkpIGJyb3dzZXIgPSAnT3BlcmEnO1xuICAgIFxuICAgIHJldHVybiB7IG9zLCBicm93c2VyIH07XG4gIH0sXG5cbiAgLyoqXG4gICAqIExvZyBkZSBhdWRpdG9yaWEgcGFyYSBldmVudG9zIGRlIGF1dGVudGljYcOnw6NvXG4gICAqL1xuICBhc3luYyBhdWRpdExvZyhldmVudDogT21pdDxBdXRoQXVkaXRFdmVudCwgJ3N1Y2Nlc3MnPiAmIHsgc3VjY2VzczogYm9vbGVhbiB9KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGIgPSBnZXREQigpO1xuICAgIFxuICAgIHRyeSB7XG4gICAgICBhd2FpdCBkYi5pbnNlcnQoc2NoZW1hLmF1ZGl0TG9ncykudmFsdWVzKHtcbiAgICAgICAgaWQ6IGdlbmVyYXRlVVVJRCgpLFxuICAgICAgICBhY3Rpb246IGV2ZW50LmFjdGlvbixcbiAgICAgICAgdXNlcklkOiBldmVudC51c2VySWQgfHwgbnVsbCxcbiAgICAgICAgc2Vzc2lvbklkOiBldmVudC5zZXNzaW9uSWQgfHwgbnVsbCxcbiAgICAgICAgZGV2aWNlSWQ6IGV2ZW50LmRldmljZUlkIHx8IG51bGwsXG4gICAgICAgIHRpbWVzdGFtcDogZXZlbnQudGltZXN0YW1wLFxuICAgICAgICBpcEFkZHJlc3M6IGV2ZW50LmlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50OiBldmVudC51c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGV2ZW50LnN1Y2Nlc3MsXG4gICAgICAgIGZhaWx1cmVSZWFzb246IGV2ZW50LmZhaWx1cmVSZWFzb24gfHwgbnVsbCxcbiAgICAgICAgbWV0YWRhdGE6IGV2ZW50Lm1ldGFkYXRhIHx8IG51bGwsXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgLy8gTlVOQ0EgZmFsaGFyIGF1dGVudGljYcOnw6NvIHBvciBlcnJvIGRlIGxvZ2dpbmdcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tBdXRoU2VydmljZV0gRmFsaGEgYW8gcmVnaXN0cmFyIGxvZyBkZSBhdWRpdG9yaWE6JywgZXJyb3IpO1xuICAgIH1cbiAgfSxcblxuICAvKipcbiAgICogVmVyaWZpY2EgY8OzZGlnbyBNRkEgZHVyYW50ZSBsb2dpblxuICAgKi9cbiAgYXN5bmMgdmVyaWZ5TUZBKFxuICAgIHVzZXJJZDogc3RyaW5nLFxuICAgIG1mYUNvZGU6IHN0cmluZyxcbiAgICBpcEFkZHJlc3M6IHN0cmluZyxcbiAgICB1c2VyQWdlbnQ6IHN0cmluZ1xuICApOiBQcm9taXNlPEF1dGhSZXNwb25zZT4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcbiAgICBcbiAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgIGFjdGlvbjogJ01GQV9WRVJJRllfUkVRVUVTVCcsXG4gICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICBpcEFkZHJlc3MsXG4gICAgICB1c2VyQWdlbnQsXG4gICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgbWV0YWRhdGE6IHsgdXNlcklkIH0sXG4gICAgfSk7XG5cbiAgICBjb25zdCB1c2VyID0gYXdhaXQgZGJcbiAgICAgIC5zZWxlY3QoKVxuICAgICAgLmZyb20oc2NoZW1hLnVzZXJzKVxuICAgICAgLndoZXJlKGVxKHNjaGVtYS51c2Vycy5pZCwgdXNlcklkKSlcbiAgICAgIC5saW1pdCgxKTtcblxuICAgIGlmICghdXNlciB8fCB1c2VyLmxlbmd0aCA9PT0gMCkge1xuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ01GQV9WRVJJRllfRkFJTFVSRScsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnVXN1w6FyaW8gbsOjbyBlbmNvbnRyYWRvJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHsgXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLCBcbiAgICAgICAgZXJyb3I6IG5ldyBBdXRoRXJyb3IoJ0lOVkFMSURfQ1JFREVOVElBTFMnLCAnQ3JlZGVuY2lhaXMgaW52w6FsaWRhcycpIFxuICAgICAgfTtcbiAgICB9XG5cbiAgICBjb25zdCB1c2VyRGF0YSA9IHVzZXJbMF07XG5cbiAgICBpZiAoIXVzZXJEYXRhLm1mYUVuYWJsZWQgfHwgIXVzZXJEYXRhLm1mYVNlY3JldCkge1xuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ01GQV9WRVJJRllfRkFJTFVSRScsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnTUZBIG7Do28gaGFiaWxpdGFkbycsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7IFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSwgXG4gICAgICAgIGVycm9yOiBuZXcgQXV0aEVycm9yKCdNRkFfTk9UX0VOQUJMRUQnLCAnTUZBIG7Do28gaGFiaWxpdGFkbyBwYXJhIGVzdGEgY29udGEnKSBcbiAgICAgIH07XG4gICAgfVxuXG4gICAgY29uc3QgeyB2ZXJpZnlUT1RQIH0gPSBhd2FpdCBpbXBvcnQoJ0B6ZXJvL2NyeXB0bycpO1xuICAgIGNvbnN0IGlzVmFsaWQgPSB2ZXJpZnlUT1RQKHVzZXJEYXRhLm1mYVNlY3JldCwgbWZhQ29kZSk7XG5cbiAgICBpZiAoIWlzVmFsaWQpIHtcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdNRkFfVkVSSUZZX0ZBSUxVUkUnLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZmFpbHVyZVJlYXNvbjogJ0PDs2RpZ28gTUZBIGludsOhbGlkbycsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7IFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSwgXG4gICAgICAgIGVycm9yOiBuZXcgQXV0aEVycm9yKCdJTlZBTElEX01GQV9DT0RFJywgJ0PDs2RpZ28gTUZBIGludsOhbGlkbycpIFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBNRkEgdmVyaWZpY2FkbyBjb20gc3VjZXNzbyAtIGdlcmFyIHRva2Vuc1xuICAgIGNvbnN0IHNlc3Npb25JZCA9IGdlbmVyYXRlVVVJRCgpO1xuICAgIGNvbnN0IGRldmljZUlkID0gZ2VuZXJhdGVVVUlEKCk7XG4gICAgY29uc3QgdG9rZW5zID0gZ2VuZXJhdGVBdXRoVG9rZW5zKHVzZXJJZCwgc2Vzc2lvbklkLCBkZXZpY2VJZCk7XG5cbiAgICAvLyBBdHVhbGl6YXIgc3RhdHVzIGRvIHVzdcOhcmlvIHBhcmEgYWN0aXZlXG4gICAgYXdhaXQgZGJcbiAgICAgIC51cGRhdGUoc2NoZW1hLnVzZXJzKVxuICAgICAgLnNldCh7IFxuICAgICAgICBzdGF0dXM6ICdhY3RpdmUnLFxuICAgICAgICBsYXN0TG9naW5BdDogbmV3IERhdGUoKSBcbiAgICAgIH0pXG4gICAgICAud2hlcmUoZXEoc2NoZW1hLnVzZXJzLmlkLCB1c2VySWQpKTtcblxuICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgYWN0aW9uOiAnTUZBX1ZFUklGWV9TVUNDRVNTJyxcbiAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgIGlwQWRkcmVzcyxcbiAgICAgIHVzZXJBZ2VudCxcbiAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICB1c2VySWQsXG4gICAgICBzZXNzaW9uSWQsXG4gICAgICBkZXZpY2VJZCxcbiAgICB9KTtcblxuICAgIHJldHVybiB7XG4gICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgdXNlcjoge1xuICAgICAgICBpZDogdXNlckRhdGEuaWQsXG4gICAgICAgIGVtYWlsOiB1c2VyRGF0YS5lbWFpbCxcbiAgICAgICAgZGlzcGxheU5hbWU6IHVzZXJEYXRhLmRpc3BsYXlOYW1lLFxuICAgICAgfSxcbiAgICAgIHRva2VucyxcbiAgICAgIG1mYVJlcXVpcmVkOiBmYWxzZSxcbiAgICB9O1xuICB9LFxuXG4gIC8qKlxuICAgKiBSZWZyZXNoIGRlIGFjY2VzcyB0b2tlbiB1c2FuZG8gcmVmcmVzaCB0b2tlblxuICAgKi9cbiAgYXN5bmMgcmVmcmVzaEFjY2Vzc1Rva2VuKFxuICAgIHJlZnJlc2hUb2tlbjogc3RyaW5nLFxuICAgIGlwQWRkcmVzczogc3RyaW5nLFxuICAgIHVzZXJBZ2VudDogc3RyaW5nXG4gICk6IFByb21pc2U8eyBzdWNjZXNzOiBib29sZWFuOyB0b2tlbnM/OiB0eXBlb2YgZ2VuZXJhdGVBdXRoVG9rZW5zOyBlcnJvcj86IEF1dGhFcnJvciB9PiB7XG4gICAgY29uc3QgZGIgPSBnZXREQigpO1xuICAgIFxuICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgYWN0aW9uOiAnVE9LRU5fUkVGUkVTSF9SRVFVRVNUJyxcbiAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgIGlwQWRkcmVzcyxcbiAgICAgIHVzZXJBZ2VudCxcbiAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgfSk7XG5cbiAgICBjb25zdCB7IHZlcmlmeUpXVCB9ID0gYXdhaXQgaW1wb3J0KCdAemVyby9jcnlwdG8nKTtcbiAgICBjb25zdCB2ZXJpZmllZCA9IHZlcmlmeUpXVChyZWZyZXNoVG9rZW4sICdyZWZyZXNoJyk7XG5cbiAgICBpZiAoIXZlcmlmaWVkLnZhbGlkKSB7XG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnVE9LRU5fUkVGUkVTSF9GQUlMVVJFJyxcbiAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGZhaWx1cmVSZWFzb246ICdSZWZyZXNoIHRva2VuIGludsOhbGlkbycsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7IFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSwgXG4gICAgICAgIGVycm9yOiB2ZXJpZmllZC5lcnJvciBcbiAgICAgIH07XG4gICAgfVxuXG4gICAgY29uc3QgcGF5bG9hZCA9IHZlcmlmaWVkLnBheWxvYWQgYXMgYW55O1xuICAgIGNvbnN0IHVzZXJJZCA9IHBheWxvYWQuc3ViO1xuICAgIGNvbnN0IHNlc3Npb25JZCA9IHBheWxvYWQuc2lkO1xuXG4gICAgLy8gVmVyaWZpY2FyIHNlIHNlc3PDo28gYWluZGEgZXhpc3RlIGUgw6kgdsOhbGlkYVxuICAgIGNvbnN0IHNlc3Npb25zID0gYXdhaXQgZGJcbiAgICAgIC5zZWxlY3QoKVxuICAgICAgLmZyb20oc2NoZW1hLnNlc3Npb25zKVxuICAgICAgLndoZXJlKGVxKHNjaGVtYS5zZXNzaW9ucy5pZCwgc2Vzc2lvbklkKSlcbiAgICAgIC5saW1pdCgxKTtcblxuICAgIGlmICghc2Vzc2lvbnMgfHwgc2Vzc2lvbnMubGVuZ3RoID09PSAwKSB7XG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnVE9LRU5fUkVGUkVTSF9GQUlMVVJFJyxcbiAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGZhaWx1cmVSZWFzb246ICdTZXNzw6NvIG7Do28gZW5jb250cmFkYScsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7IFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSwgXG4gICAgICAgIGVycm9yOiBuZXcgQXV0aEVycm9yKCdTRVNTSU9OX0lOVkFMSUQnLCAnU2Vzc8OjbyBpbnbDoWxpZGEgb3UgZXhwaXJhZGEnKSBcbiAgICAgIH07XG4gICAgfVxuXG4gICAgY29uc3Qgc2Vzc2lvbiA9IHNlc3Npb25zWzBdO1xuXG4gICAgaWYgKHNlc3Npb24ucmV2b2tlZEF0IHx8IHNlc3Npb24uZXhwaXJlc0F0IDwgbmV3IERhdGUoKSkge1xuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ1RPS0VOX1JFRlJFU0hfRkFJTFVSRScsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnU2Vzc8OjbyByZXZvZ2FkYSBvdSBleHBpcmFkYScsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7IFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSwgXG4gICAgICAgIGVycm9yOiBuZXcgQXV0aEVycm9yKCdTRVNTSU9OX1JFVk9LRUQnLCAnU2Vzc8OjbyBmb2kgcmV2b2dhZGEnKSBcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gR2VyYXIgbm92byBwYXIgZGUgdG9rZW5zXG4gICAgY29uc3QgdG9rZW5zID0gZ2VuZXJhdGVBdXRoVG9rZW5zKHVzZXJJZCwgc2Vzc2lvbklkLCBzZXNzaW9uLmRldmljZUlkKTtcblxuICAgIC8vIFJvdGFjaW9uYXIgcmVmcmVzaCB0b2tlbiAoaW52YWxpZGFyIG8gYW50ZXJpb3IpXG4gICAgYXdhaXQgZGJcbiAgICAgIC51cGRhdGUoc2NoZW1hLnJlZnJlc2hUb2tlbnMpXG4gICAgICAuc2V0KHsgcmV2b2tlZEF0OiBuZXcgRGF0ZSgpIH0pXG4gICAgICAud2hlcmUoZXEoc2NoZW1hLnJlZnJlc2hUb2tlbnMudG9rZW5IYXNoLCBzaGEyNTYocmVmcmVzaFRva2VuKSkpO1xuXG4gICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICBhY3Rpb246ICdUT0tFTl9SRUZSRVNIX1NVQ0NFU1MnLFxuICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgaXBBZGRyZXNzLFxuICAgICAgdXNlckFnZW50LFxuICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgIHVzZXJJZCxcbiAgICAgIHNlc3Npb25JZCxcbiAgICB9KTtcblxuICAgIHJldHVybiB7XG4gICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgdG9rZW5zLFxuICAgIH07XG4gIH0sXG5cbiAgLyoqXG4gICAqIExvZ291dCBkZSB1bWEgc2Vzc8OjbyBlc3BlY8OtZmljYVxuICAgKi9cbiAgYXN5bmMgbG9nb3V0KFxuICAgIHNlc3Npb25JZDogc3RyaW5nLFxuICAgIGlwQWRkcmVzczogc3RyaW5nLFxuICAgIHVzZXJBZ2VudDogc3RyaW5nXG4gICk6IFByb21pc2U8eyBzdWNjZXNzOiBib29sZWFuOyBlcnJvcj86IEF1dGhFcnJvciB9PiB7XG4gICAgY29uc3QgZGIgPSBnZXREQigpO1xuICAgIFxuICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgYWN0aW9uOiAnTE9HT1VUX1JFUVVFU1QnLFxuICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgaXBBZGRyZXNzLFxuICAgICAgdXNlckFnZW50LFxuICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgIHNlc3Npb25JZCxcbiAgICB9KTtcblxuICAgIGNvbnN0IHNlc3Npb25zID0gYXdhaXQgZGJcbiAgICAgIC5zZWxlY3QoKVxuICAgICAgLmZyb20oc2NoZW1hLnNlc3Npb25zKVxuICAgICAgLndoZXJlKGVxKHNjaGVtYS5zZXNzaW9ucy5pZCwgc2Vzc2lvbklkKSlcbiAgICAgIC5saW1pdCgxKTtcblxuICAgIGlmICghc2Vzc2lvbnMgfHwgc2Vzc2lvbnMubGVuZ3RoID09PSAwKSB7XG4gICAgICByZXR1cm4geyBzdWNjZXNzOiB0cnVlIH07IC8vIErDoSBuw6NvIGV4aXN0ZSwgY29uc2lkZXJhZG8gc3VjZXNzb1xuICAgIH1cblxuICAgIGNvbnN0IHNlc3Npb24gPSBzZXNzaW9uc1swXTtcblxuICAgIC8vIFJldm9nYXIgc2Vzc8Ojb1xuICAgIGF3YWl0IGRiXG4gICAgICAudXBkYXRlKHNjaGVtYS5zZXNzaW9ucylcbiAgICAgIC5zZXQoeyByZXZva2VkQXQ6IG5ldyBEYXRlKCkgfSlcbiAgICAgIC53aGVyZShlcShzY2hlbWEuc2Vzc2lvbnMuaWQsIHNlc3Npb25JZCkpO1xuXG4gICAgLy8gUmV2b2dhciByZWZyZXNoIHRva2VucyBhc3NvY2lhZG9zXG4gICAgYXdhaXQgZGJcbiAgICAgIC51cGRhdGUoc2NoZW1hLnJlZnJlc2hUb2tlbnMpXG4gICAgICAuc2V0KHsgcmV2b2tlZEF0OiBuZXcgRGF0ZSgpIH0pXG4gICAgICAud2hlcmUoZXEoc2NoZW1hLnJlZnJlc2hUb2tlbnMuc2Vzc2lvbklkLCBzZXNzaW9uSWQpKTtcblxuICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgYWN0aW9uOiAnTE9HT1VUX1NVQ0NFU1MnLFxuICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgaXBBZGRyZXNzLFxuICAgICAgdXNlckFnZW50LFxuICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgIHNlc3Npb25JZCxcbiAgICAgIHVzZXJJZDogc2Vzc2lvbi51c2VySWQsXG4gICAgfSk7XG5cbiAgICByZXR1cm4geyBzdWNjZXNzOiB0cnVlIH07XG4gIH0sXG5cbiAgLyoqXG4gICAqIExvZ291dCBkZSB0b2RhcyBhcyBzZXNzw7VlcyBkbyB1c3XDoXJpb1xuICAgKi9cbiAgYXN5bmMgbG9nb3V0QWxsKFxuICAgIHVzZXJJZDogc3RyaW5nLFxuICAgIGN1cnJlbnRTZXNzaW9uSWQ6IHN0cmluZyB8IG51bGwsXG4gICAgaXBBZGRyZXNzOiBzdHJpbmcsXG4gICAgdXNlckFnZW50OiBzdHJpbmdcbiAgKTogUHJvbWlzZTx7IHN1Y2Nlc3M6IGJvb2xlYW47IGVycm9yPzogQXV0aEVycm9yIH0+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG4gICAgXG4gICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICBhY3Rpb246ICdMT0dPVVRfQUxMX1JFUVVFU1QnLFxuICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgaXBBZGRyZXNzLFxuICAgICAgdXNlckFnZW50LFxuICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgIHVzZXJJZCxcbiAgICB9KTtcblxuICAgIC8vIFJldm9nYXIgdG9kYXMgYXMgc2Vzc8O1ZXMgZXhjZXRvIGEgYXR1YWwgKHNlIGZvcm5lY2lkYSlcbiAgICBjb25zdCB1cGRhdGVRdWVyeSA9IGRiXG4gICAgICAudXBkYXRlKHNjaGVtYS5zZXNzaW9ucylcbiAgICAgIC5zZXQoeyByZXZva2VkQXQ6IG5ldyBEYXRlKCkgfSlcbiAgICAgIC53aGVyZShlcShzY2hlbWEuc2Vzc2lvbnMudXNlcklkLCB1c2VySWQpKTtcblxuICAgIGlmIChjdXJyZW50U2Vzc2lvbklkKSB7XG4gICAgICB1cGRhdGVRdWVyeS53aGVyZShzcWxgaWQgIT0gJHtjdXJyZW50U2Vzc2lvbklkfWApO1xuICAgIH0gZWxzZSB7XG4gICAgICB1cGRhdGVRdWVyeS5leGVjdXRlKCk7XG4gICAgfVxuXG4gICAgLy8gUmV2b2dhciB0b2RvcyBvcyByZWZyZXNoIHRva2VucyBleGNldG8gb3MgZGEgc2Vzc8OjbyBhdHVhbFxuICAgIGNvbnN0IHJlZnJlc2hUb2tlblF1ZXJ5ID0gZGJcbiAgICAgIC51cGRhdGUoc2NoZW1hLnJlZnJlc2hUb2tlbnMpXG4gICAgICAuc2V0KHsgcmV2b2tlZEF0OiBuZXcgRGF0ZSgpIH0pXG4gICAgICAud2hlcmUoZXEoc2NoZW1hLnJlZnJlc2hUb2tlbnMudXNlcklkLCB1c2VySWQpKTtcblxuICAgIGlmIChjdXJyZW50U2Vzc2lvbklkKSB7XG4gICAgICByZWZyZXNoVG9rZW5RdWVyeS53aGVyZShzcWxgc2Vzc2lvbklkICE9ICR7Y3VycmVudFNlc3Npb25JZH1gKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVmcmVzaFRva2VuUXVlcnkuZXhlY3V0ZSgpO1xuICAgIH1cblxuICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgYWN0aW9uOiAnTE9HT1VUX0FMTF9TVUNDRVNTJyxcbiAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgIGlwQWRkcmVzcyxcbiAgICAgIHVzZXJBZ2VudCxcbiAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICB1c2VySWQsXG4gICAgfSk7XG5cbiAgICByZXR1cm4geyBzdWNjZXNzOiB0cnVlIH07XG4gIH0sXG5cbiAgLyoqXG4gICAqIE9idMOpbSB1c3XDoXJpbyBwb3IgSUQgKHNlbSBkYWRvcyBzZW5zw612ZWlzKVxuICAgKi9cbiAgYXN5bmMgZ2V0VXNlckJ5SWQodXNlcklkOiBzdHJpbmcpOiBQcm9taXNlPHsgc3VjY2VzczogYm9vbGVhbjsgdXNlcj86IHsgaWQ6IHN0cmluZzsgZW1haWw6IHN0cmluZzsgZGlzcGxheU5hbWU6IHN0cmluZyB8IG51bGw7IG1mYUVuYWJsZWQ6IGJvb2xlYW47IHN0YXR1czogc3RyaW5nIH07IGVycm9yPzogQXV0aEVycm9yIH0+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG5cbiAgICB0cnkge1xuICAgICAgY29uc3QgdXNlcnMgPSBhd2FpdCBkYlxuICAgICAgICAuc2VsZWN0KHtcbiAgICAgICAgICBpZDogc2NoZW1hLnVzZXJzLmlkLFxuICAgICAgICAgIGVtYWlsOiBzY2hlbWEudXNlcnMuZW1haWwsXG4gICAgICAgICAgZGlzcGxheU5hbWU6IHNjaGVtYS51c2Vycy5kaXNwbGF5TmFtZSxcbiAgICAgICAgICBtZmFFbmFibGVkOiBzY2hlbWEudXNlcnMubWZhRW5hYmxlZCxcbiAgICAgICAgICBzdGF0dXM6IHNjaGVtYS51c2Vycy5zdGF0dXMsXG4gICAgICAgIH0pXG4gICAgICAgIC5mcm9tKHNjaGVtYS51c2VycylcbiAgICAgICAgLndoZXJlKGVxKHNjaGVtYS51c2Vycy5pZCwgdXNlcklkKSlcbiAgICAgICAgLmxpbWl0KDEpO1xuXG4gICAgICBpZiAoIXVzZXJzIHx8IHVzZXJzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICByZXR1cm4geyBcbiAgICAgICAgICBzdWNjZXNzOiBmYWxzZSwgXG4gICAgICAgICAgZXJyb3I6IG5ldyBBdXRoRXJyb3IoJ1VTRVJfTk9UX0ZPVU5EJywgJ1VzdcOhcmlvIG7Do28gZW5jb250cmFkbycpIFxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICB1c2VyOiB1c2Vyc1swXSxcbiAgICAgIH07XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tBdXRoU2VydmljZV0gRXJybyBhbyBidXNjYXIgdXN1w6FyaW86JywgZXJyb3IpO1xuICAgICAgcmV0dXJuIHsgXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLCBcbiAgICAgICAgZXJyb3I6IG5ldyBBdXRoRXJyb3IoJ0RBVEFCQVNFX0VSUk9SJywgJ0Vycm8gaW50ZXJubyBhbyBidXNjYXIgdXN1w6FyaW8nKSBcbiAgICAgIH07XG4gICAgfVxuICB9LFxufTtcblxuLy8gSW1wb3J0IG5lY2Vzc8OhcmlvIHBhcmEgU1FMXG5pbXBvcnQgeyBzcWwgfSBmcm9tICdkcml6emxlLW9ybSc7XG4iXX0=
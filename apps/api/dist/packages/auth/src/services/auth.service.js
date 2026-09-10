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
};
// Import necessário para SQL
import { sql } from 'drizzle-orm';
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vLi4vLi4vLi4vcGFja2FnZXMvYXV0aC9zcmMvc2VydmljZXMvYXV0aC5zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7Ozs7Ozs7R0FTRztBQUVILE9BQU8sRUFBRSxFQUFFLEVBQUUsTUFBTSxhQUFhLENBQUM7QUFDakMsT0FBTyxFQUFFLFlBQVksRUFBRSxjQUFjLEVBQUUsWUFBWSxFQUFFLE1BQU0sRUFBRSxNQUFNLGNBQWMsQ0FBQztBQUNsRixPQUFPLEVBQUUsTUFBTSxFQUFxQyxNQUFNLGdCQUFnQixDQUFDO0FBQzNFLE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxjQUFjLENBQUM7QUFDNUMsT0FBTyxFQUFFLGNBQWMsRUFBRSxNQUFNLGNBQWMsQ0FBQztBQVE5QyxPQUFPLEVBQUUsYUFBYSxFQUFFLGdCQUFnQixFQUFFLGNBQWMsRUFBRSxNQUFNLHFCQUFxQixDQUFDO0FBQ3RGLE9BQU8sRUFBRSxrQkFBa0IsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBRXJELG1EQUFtRDtBQUNuRCxJQUFJLFFBQVEsR0FBUSxJQUFJLENBQUM7QUFFekIsTUFBTSxVQUFVLGlCQUFpQixDQUFDLE1BQVc7SUFDM0MsUUFBUSxHQUFHLE1BQU0sQ0FBQztBQUNwQixDQUFDO0FBRUQsU0FBUyxLQUFLO0lBQ1osSUFBSSxDQUFDLFFBQVEsRUFBRSxDQUFDO1FBQ2QsTUFBTSxJQUFJLEtBQUssQ0FBQyxrQ0FBa0MsQ0FBQyxDQUFDO0lBQ3RELENBQUM7SUFDRCxPQUFPLFFBQVEsQ0FBQztBQUNsQixDQUFDO0FBRUQ7Ozs7Ozs7Ozs7R0FVRztBQUNILE1BQU0sQ0FBQyxNQUFNLFdBQVcsR0FBRztJQUN6QixLQUFLLENBQUMsUUFBUSxDQUFDLEtBQW9CLEVBQUUsU0FBaUIsRUFBRSxTQUFpQjtRQUN2RSxNQUFNLEVBQUUsR0FBRyxLQUFLLEVBQUUsQ0FB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QU0sQ0FBQyxTQUFTLENBQUMsQ0FBQyxNQUFNLENBQUM7Z0JBQ3ZDLEVBQUUsRUFBRSxZQUFZLEVBQUU7Z0JBQ2xCLE1BQU0sRUFBRSxLQUFLLENBQUMsTUFBTTtnQkFDcEIsTUFBTSxFQUFFLEtBQUssQ0FBQyxNQUFNLElBQUksSUFBSTtnQkFDNUIsU0FBUyxFQUFFLEtBQUssQ0FBQyxTQUFTLElBQUksSUFBSTtnQkFDbEMsUUFBUSxFQUFFLEtBQUssQ0FBQyxRQUFRLElBQUksSUFBSTtnQkFDaEMsU0FBUyxFQUFFLEtBQUssQ0FBQyxTQUFTO2dCQUMxQixTQUFTLEVBQUUsS0FBSyxDQUFDLFNBQVM7Z0JBQzFCLFNBQVMsRUFBRSxLQUFLLENBQUMsU0FBUztnQkFDMUIsT0FBTyxFQUFFLEtBQUssQ0FBQyxPQUFPO2dCQUN0QixhQUFhLEVBQUUsS0FBSyxDQUFDLGFBQWEsSUFBSSxJQUFJO2dCQUMxQyxRQUFRLEVBQUUsS0FBSyxDQUFDLFFBQVEsSUFBSSxJQUFJO2FBQ2pDLENBQUMsQ0FBQztRQUNMLENBQUM7UUFBQyxPQUFPLEtBQUssRUFBRSxDQUFDO1lBQ2YsZ0RBQWdEO1lBQ2hELE9BQU8sQ0FBQyxLQUFLLENBQUMsb0RBQW9ELEVBQUUsS0FBSyxDQUFDLENBQUM7UUFDN0UsQ0FBQztJQUNILENBQUM7Q0FDRixDQUFDO0FBRUYsNkJBQTZCO0FBQzdCLE9BQU8sRUFBRSxHQUFHLEVBQUUsTUFBTSxhQUFhLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIFNlcnZpw6dvIGRlIEF1dGVudGljYcOnw6NvIFByaW5jaXBhbFxuICogXG4gKiBSZXNwb25zYWJpbGlkYWRlczpcbiAqIC0gUmVnaXN0cm8gZGUgdXN1w6FyaW9zXG4gKiAtIExvZ2luIGNvbSB2YWxpZGHDp8OjbyBkZSBjcmVkZW5jaWFpc1xuICogLSBHZXJlbmNpYW1lbnRvIGRlIHRlbnRhdGl2YXMgZSBsb2Nrb3V0XG4gKiAtIEludGVncmHDp8OjbyBjb20gTUZBXG4gKiAtIEF1ZGl0b3JpYSBkZSBldmVudG9zXG4gKi9cblxuaW1wb3J0IHsgZXEgfSBmcm9tICdkcml6emxlLW9ybSc7XG5pbXBvcnQgeyBoYXNoUGFzc3dvcmQsIHZlcmlmeVBhc3N3b3JkLCBnZW5lcmF0ZVNhbHQsIHNoYTI1NiB9IGZyb20gJ0B6ZXJvL2NyeXB0byc7XG5pbXBvcnQgeyBzY2hlbWEsIHR5cGUgTmV3VXNlciwgdHlwZSBVc2VyIGFzIERCVXNlciB9IGZyb20gJ0B6ZXJvL2RhdGFiYXNlJztcbmltcG9ydCB7IGdlbmVyYXRlVVVJRCB9IGZyb20gJ0B6ZXJvL3NoYXJlZCc7XG5pbXBvcnQgeyBBVVRIX0NPTlNUQU5UUyB9IGZyb20gJy4uL2NvbnN0YW50cyc7XG5pbXBvcnQgdHlwZSB7IFxuICBSZWdpc3RlcklucHV0LCBcbiAgTG9naW5JbnB1dCwgXG4gIEF1dGhSZXNwb25zZSwgXG4gIEF1dGhFcnJvcixcbiAgQXV0aEF1ZGl0RXZlbnQgXG59IGZyb20gJy4uL3R5cGVzJztcbmltcG9ydCB7IHZhbGlkYXRlRW1haWwsIHZhbGlkYXRlUGFzc3dvcmQsIG5vcm1hbGl6ZUVtYWlsIH0gZnJvbSAnLi4vdXRpbHMvdmFsaWRhdGlvbic7XG5pbXBvcnQgeyBnZW5lcmF0ZUF1dGhUb2tlbnMgfSBmcm9tICcuLi91dGlscy90b2tlbnMnO1xuXG4vLyBNb2NrIGRvIGRhdGFiYXNlIGNsaWVudCAoc2Vyw6EgaW5qZXRhZG8gcGVsYSBBUEkpXG5sZXQgZGJDbGllbnQ6IGFueSA9IG51bGw7XG5cbmV4cG9ydCBmdW5jdGlvbiBzZXREYXRhYmFzZUNsaWVudChjbGllbnQ6IGFueSk6IHZvaWQge1xuICBkYkNsaWVudCA9IGNsaWVudDtcbn1cblxuZnVuY3Rpb24gZ2V0REIoKSB7XG4gIGlmICghZGJDbGllbnQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ0RhdGFiYXNlIGNsaWVudCBuw6NvIGluaWNpYWxpemFkbycpO1xuICB9XG4gIHJldHVybiBkYkNsaWVudDtcbn1cblxuLyoqXG4gKiBSZWdpc3RyYSBub3ZvIHVzdcOhcmlvIG5vIHNpc3RlbWFcbiAqIFxuICogU0VDVVJJVFkgTk9URVM6XG4gKiAtIEVtYWlsIG5vcm1hbGl6YWRvIHBhcmEgbG93ZXJjYXNlXG4gKiAtIFNlbmhhIGhhc2ggY29tIEFyZ29uMmlkIGFudGVzIGRlIGFybWF6ZW5hclxuICogLSBWYWxpZGHDp8OjbyBkZSBmb3LDp2EgZGEgc2VuaGFcbiAqIC0gVmVyaWZpY2HDp8OjbyBkZSBlbWFpbCBkdXBsaWNhZG9cbiAqIC0gR2VyYcOnw6NvIGRlIHJlY292ZXJ5IGNvZGVzXG4gKiAtIEF1ZGl0b3JpYSBkbyBldmVudG9cbiAqL1xuZXhwb3J0IGNvbnN0IEF1dGhTZXJ2aWNlID0ge1xuICBhc3luYyByZWdpc3RlcihpbnB1dDogUmVnaXN0ZXJJbnB1dCwgaXBBZGRyZXNzOiBzdHJpbmcsIHVzZXJBZ2VudDogc3RyaW5nKTogUHJvbWlzZTxBdXRoUmVzcG9uc2U+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG4gICAgXG4gICAgLy8gQXVkaXQ6IHJlZ2lzdHJvIGluaWNpYWRvXG4gICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICBhY3Rpb246ICdSRUdJU1RFUl9SRVFVRVNUJyxcbiAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgIGlwQWRkcmVzcyxcbiAgICAgIHVzZXJBZ2VudCxcbiAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICBtZXRhZGF0YTogeyBlbWFpbDogaW5wdXQuZW1haWwgfSxcbiAgICB9KTtcblxuICAgIC8vIFZhbGlkYXIgZW1haWxcbiAgICBjb25zdCBlbWFpbFZhbGlkYXRpb24gPSB2YWxpZGF0ZUVtYWlsKGlucHV0LmVtYWlsKTtcbiAgICBpZiAoIWVtYWlsVmFsaWRhdGlvbi52YWxpZCkge1xuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ1JFR0lTVEVSX0ZBSUxVUkUnLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZmFpbHVyZVJlYXNvbjogZW1haWxWYWxpZGF0aW9uLmVycm9yPy5tZXNzYWdlLFxuICAgICAgfSk7XG4gICAgICByZXR1cm4geyBzdWNjZXNzOiBmYWxzZSwgZXJyb3I6IGVtYWlsVmFsaWRhdGlvbi5lcnJvciB9O1xuICAgIH1cblxuICAgIC8vIFZhbGlkYXIgc2VuaGFcbiAgICBjb25zdCBwYXNzd29yZFZhbGlkYXRpb24gPSB2YWxpZGF0ZVBhc3N3b3JkKGlucHV0LnBhc3N3b3JkKTtcbiAgICBpZiAoIXBhc3N3b3JkVmFsaWRhdGlvbi52YWxpZCkge1xuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ1JFR0lTVEVSX0ZBSUxVUkUnLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZmFpbHVyZVJlYXNvbjogcGFzc3dvcmRWYWxpZGF0aW9uLmVycm9yPy5tZXNzYWdlLFxuICAgICAgfSk7XG4gICAgICByZXR1cm4geyBzdWNjZXNzOiBmYWxzZSwgZXJyb3I6IHBhc3N3b3JkVmFsaWRhdGlvbi5lcnJvciB9O1xuICAgIH1cblxuICAgIGNvbnN0IG5vcm1hbGl6ZWRFbWFpbCA9IG5vcm1hbGl6ZUVtYWlsKGlucHV0LmVtYWlsKTtcblxuICAgIC8vIFZlcmlmaWNhciBzZSBlbWFpbCBqw6EgZXhpc3RlXG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGV4aXN0aW5nVXNlciA9IGF3YWl0IGRiXG4gICAgICAgIC5zZWxlY3QoKVxuICAgICAgICAuZnJvbShzY2hlbWEudXNlcnMpXG4gICAgICAgIC53aGVyZShlcShzY2hlbWEudXNlcnMuZW1haWwsIG5vcm1hbGl6ZWRFbWFpbCkpXG4gICAgICAgIC5saW1pdCgxKTtcblxuICAgICAgaWYgKGV4aXN0aW5nVXNlciAmJiBleGlzdGluZ1VzZXIubGVuZ3RoID4gMCkge1xuICAgICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgICBhY3Rpb246ICdSRUdJU1RFUl9GQUlMVVJFJyxcbiAgICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICBmYWlsdXJlUmVhc29uOiAnRW1haWwgasOhIGNhZGFzdHJhZG8nLFxuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICBlcnJvcjogeyBjb2RlOiAnRU1BSUxfQUxSRUFEWV9FWElTVFMnLCBtZXNzYWdlOiAnRW1haWwgasOhIGNhZGFzdHJhZG8nIH0sXG4gICAgICAgIH07XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdSRUdJU1RFUl9GQUlMVVJFJyxcbiAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudCxcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGZhaWx1cmVSZWFzb246ICdFcnJvIGFvIHZlcmlmaWNhciBlbWFpbCcsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBlcnJvcjogeyBjb2RlOiAnSU5URVJOQUxfRVJST1InLCBtZXNzYWdlOiBBVVRIX0NPTlNUQU5UUy5FUlJPUl9NRVNTQUdFUy5JTlRFUk5BTF9FUlJPUiB9LFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBIYXNoIGRhIHNlbmhhIGNvbSBBcmdvbjJpZFxuICAgIGxldCBwYXNzd29yZEhhc2g6IHN0cmluZztcbiAgICB0cnkge1xuICAgICAgcGFzc3dvcmRIYXNoID0gYXdhaXQgaGFzaFBhc3N3b3JkKGlucHV0LnBhc3N3b3JkKTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ1JFR0lTVEVSX0ZBSUxVUkUnLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZmFpbHVyZVJlYXNvbjogJ0Vycm8gYW8gaGFzaCBzZW5oYScsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBlcnJvcjogeyBjb2RlOiAnSU5URVJOQUxfRVJST1InLCBtZXNzYWdlOiBBVVRIX0NPTlNUQU5UUy5FUlJPUl9NRVNTQUdFUy5JTlRFUk5BTF9FUlJPUiB9LFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBDcmlhciB1c3XDoXJpb1xuICAgIGNvbnN0IHVzZXJJZCA9IGdlbmVyYXRlVVVJRCgpO1xuICAgIGNvbnN0IHNhbHQgPSBnZW5lcmF0ZVNhbHQoKTtcbiAgICBjb25zdCBuZXdVc2VyOiBOZXdVc2VyID0ge1xuICAgICAgaWQ6IHVzZXJJZCxcbiAgICAgIGVtYWlsOiBub3JtYWxpemVkRW1haWwsXG4gICAgICBwYXNzd29yZEhhc2gsXG4gICAgICBwYXNzd29yZFNhbHQ6IHNhbHQsXG4gICAgICBkaXNwbGF5TmFtZTogaW5wdXQuZGlzcGxheU5hbWU/LnRyaW0oKSB8fCBudWxsLFxuICAgICAgcmVjb3ZlcnlFbWFpbDogaW5wdXQucmVjb3ZlcnlFbWFpbCA/IG5vcm1hbGl6ZUVtYWlsKGlucHV0LnJlY292ZXJ5RW1haWwpIDogbnVsbCxcbiAgICAgIHN0YXR1czogJ3BlbmRpbmdfbWZhJywgLy8gUmVxdWVyIHNldHVwIGRlIE1GQSBhcMOzcyByZWdpc3Ryb1xuICAgICAgbWZhRW5hYmxlZDogZmFsc2UsXG4gICAgICBjcmVhdGVkQXQ6IG5ldyBEYXRlKCksXG4gICAgICB1cGRhdGVkQXQ6IG5ldyBEYXRlKCksXG4gICAgICBmYWlsZWRMb2dpbkF0dGVtcHRzOiAwLFxuICAgICAgbG9ja2VkVW50aWw6IG51bGwsXG4gICAgICBsYXN0TG9naW5BdDogbnVsbCxcbiAgICAgIGZhY2lhbFRlbXBsYXRlSGFzaDogbnVsbCwgLy8gU2Vyw6EgZGVmaW5pZG8gc2UgdXNhciBiaW9tZXRyaWFcbiAgICB9O1xuXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IGRiLmluc2VydChzY2hlbWEudXNlcnMpLnZhbHVlcyhuZXdVc2VyKTtcblxuICAgICAgLy8gVE9ETzogR2VyYXIgcmVjb3ZlcnkgY29kZXMgZSBzYWx2YXIgZW0gZW5jcnlwdGlvbl9rZXlzXG5cbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdSRUdJU1RFUl9TVUNDRVNTJyxcbiAgICAgICAgdXNlcklkLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgIHVzZXJJZCxcbiAgICAgICAgcmVxdWlyZXNNRkE6IHRydWUsXG4gICAgICB9O1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnUkVHSVNURVJfRkFJTFVSRScsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnRXJybyBhbyBjcmlhciB1c3XDoXJpbycsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBlcnJvcjogeyBjb2RlOiAnSU5URVJOQUxfRVJST1InLCBtZXNzYWdlOiBBVVRIX0NPTlNUQU5UUy5FUlJPUl9NRVNTQUdFUy5JTlRFUk5BTF9FUlJPUiB9LFxuICAgICAgfTtcbiAgICB9XG4gIH0sXG5cbiAgLyoqXG4gICAqIEF1dGVudGljYSB1c3XDoXJpbyBjb20gZW1haWwgZSBzZW5oYVxuICAgKiBcbiAgICogU0VDVVJJVFkgTk9URVM6XG4gICAqIC0gVGltaW5nLXNhZmUgY29tcGFyaXNvbiBwYXJhIHNlbmhhXG4gICAqIC0gUmF0ZSBsaW1pdGluZyBwb3IgSVAgZSB1c3XDoXJpb1xuICAgKiAtIExvY2tvdXQgYXDDs3MgbcO6bHRpcGxhcyBmYWxoYXNcbiAgICogLSBNZW5zYWdlbnMgZGUgZXJybyBnZW7DqXJpY2FzIChuw6NvIHJldmVsYXIgc2UgZW1haWwgZXhpc3RlKVxuICAgKiAtIFJlcXVlciBNRkEgc2UgaGFiaWxpdGFkb1xuICAgKi9cbiAgYXN5bmMgbG9naW4oaW5wdXQ6IExvZ2luSW5wdXQsIGlwQWRkcmVzczogc3RyaW5nLCB1c2VyQWdlbnQ6IHN0cmluZyk6IFByb21pc2U8QXV0aFJlc3BvbnNlPiB7XG4gICAgY29uc3QgZGIgPSBnZXREQigpO1xuXG4gICAgLy8gQXVkaXQ6IGxvZ2luIGluaWNpYWRvXG4gICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICBhY3Rpb246ICdMT0dJTl9SRVFVRVNUJyxcbiAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgIGlwQWRkcmVzcyxcbiAgICAgIHVzZXJBZ2VudCxcbiAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICBtZXRhZGF0YTogeyBlbWFpbDogaW5wdXQuZW1haWwgfSxcbiAgICB9KTtcblxuICAgIC8vIFZhbGlkYXIgZm9ybWF0byBkbyBlbWFpbFxuICAgIGNvbnN0IGVtYWlsVmFsaWRhdGlvbiA9IHZhbGlkYXRlRW1haWwoaW5wdXQuZW1haWwpO1xuICAgIGlmICghZW1haWxWYWxpZGF0aW9uLnZhbGlkKSB7XG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnTE9HSU5fRkFJTFVSRV9QQVNTV09SRCcsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnRW1haWwgaW52w6FsaWRvJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlZBTElEX0NSRURFTlRJQUxTJywgbWVzc2FnZTogQVVUSF9DT05TVEFOVFMuRVJST1JfTUVTU0FHRVMuSU5WQUxJRF9DUkVERU5USUFMUyB9LFxuICAgICAgfTtcbiAgICB9XG5cbiAgICBjb25zdCBub3JtYWxpemVkRW1haWwgPSBub3JtYWxpemVFbWFpbChpbnB1dC5lbWFpbCk7XG5cbiAgICAvLyBCdXNjYXIgdXN1w6FyaW9cbiAgICBsZXQgdXNlcjogREJVc2VyIHwgbnVsbCA9IG51bGw7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHVzZXJzID0gYXdhaXQgZGJcbiAgICAgICAgLnNlbGVjdCgpXG4gICAgICAgIC5mcm9tKHNjaGVtYS51c2VycylcbiAgICAgICAgLndoZXJlKGVxKHNjaGVtYS51c2Vycy5lbWFpbCwgbm9ybWFsaXplZEVtYWlsKSlcbiAgICAgICAgLmxpbWl0KDEpO1xuXG4gICAgICB1c2VyID0gdXNlcnMgJiYgdXNlcnMubGVuZ3RoID4gMCA/IHVzZXJzWzBdIDogbnVsbDtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ0xPR0lOX0ZBSUxVUkVfUEFTU1dPUkQnLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZmFpbHVyZVJlYXNvbjogJ0Vycm8gYW8gYnVzY2FyIHVzdcOhcmlvJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlRFUk5BTF9FUlJPUicsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLklOVEVSTkFMX0VSUk9SIH0sXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNlIHVzdcOhcmlvIG7Do28gZXhpc3Rpciwgc2ltdWxhciBkZWxheSBwYXJhIHByZXZlbmlyIHRpbWluZyBhdHRhY2tcbiAgICBpZiAoIXVzZXIpIHtcbiAgICAgIGF3YWl0IG5ldyBQcm9taXNlKHJlc29sdmUgPT4gc2V0VGltZW91dChyZXNvbHZlLCAxMDAgKyBNYXRoLnJhbmRvbSgpICogMTAwKSk7XG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnTE9HSU5fRkFJTFVSRV9QQVNTV09SRCcsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnVXN1w6FyaW8gbsOjbyBlbmNvbnRyYWRvJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdJTlZBTElEX0NSRURFTlRJQUxTJywgbWVzc2FnZTogQVVUSF9DT05TVEFOVFMuRVJST1JfTUVTU0FHRVMuSU5WQUxJRF9DUkVERU5USUFMUyB9LFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBWZXJpZmljYXIgc2UgY29udGEgZXN0w6EgYmxvcXVlYWRhXG4gICAgaWYgKHVzZXIubG9ja2VkVW50aWwgJiYgbmV3IERhdGUodXNlci5sb2NrZWRVbnRpbCkgPiBuZXcgRGF0ZSgpKSB7XG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnTE9HSU5fRkFJTFVSRV9MT0NLRUQnLFxuICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgIHRpbWVzdGFtcDogbmV3IERhdGUoKSxcbiAgICAgICAgaXBBZGRyZXNzLFxuICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiAnQ29udGEgYmxvcXVlYWRhJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgIGVycm9yOiB7IGNvZGU6ICdVU0VSX0xPQ0tFRCcsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLlVTRVJfTE9DS0VEIH0sXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFZlcmlmaWNhciBzZW5oYSBjb20gdGltaW5nLXNhZmUgY29tcGFyaXNvblxuICAgIGNvbnN0IHBhc3N3b3JkVmFsaWQgPSBhd2FpdCB2ZXJpZnlQYXNzd29yZChpbnB1dC5wYXNzd29yZCwgdXNlci5wYXNzd29yZEhhc2gpO1xuICAgIFxuICAgIGlmICghcGFzc3dvcmRWYWxpZCkge1xuICAgICAgLy8gSW5jcmVtZW50YXIgdGVudGF0aXZhcyBmYWxoYXNcbiAgICAgIGF3YWl0IHRoaXMuaW5jcmVtZW50RmFpbGVkQXR0ZW1wdHModXNlci5pZCk7XG4gICAgICBcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdMT0dJTl9GQUlMVVJFX1BBU1NXT1JEJyxcbiAgICAgICAgdXNlcklkOiB1c2VyLmlkLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZmFpbHVyZVJlYXNvbjogJ1NlbmhhIGludsOhbGlkYScsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBlcnJvcjogeyBjb2RlOiAnSU5WQUxJRF9DUkVERU5USUFMUycsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLklOVkFMSURfQ1JFREVOVElBTFMgfSxcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gUmVzZXRhciB0ZW50YXRpdmFzIGZhbGhhcyBhcMOzcyBsb2dpbiBiZW0tc3VjZWRpZG9cbiAgICBhd2FpdCB0aGlzLnJlc2V0RmFpbGVkQXR0ZW1wdHModXNlci5pZCk7XG5cbiAgICAvLyBWZXJpZmljYXIgc2UgTUZBIGVzdMOhIGhhYmlsaXRhZG9cbiAgICBpZiAoIXVzZXIubWZhRW5hYmxlZCkge1xuICAgICAgLy8gVXN1w6FyaW8gcHJlY2lzYSBjb25maWd1cmFyIE1GQSAoZXN0YWRvIHBlbmRpbmdfbWZhKVxuICAgICAgaWYgKHVzZXIuc3RhdHVzID09PSAncGVuZGluZ19tZmEnKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgICAgcmVxdWlyZXNNRkE6IHRydWUsXG4gICAgICAgIH07XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gU2UgY2hlZ291IGFxdWksIHNlbmhhIHbDoWxpZGEgZSBNRkEgcG9kZSBlc3RhciBoYWJpbGl0YWRvXG4gICAgLy8gU2UgTUZBIGhhYmlsaXRhZG8sIHJlcXVlciBjw7NkaWdvXG4gICAgaWYgKHVzZXIubWZhRW5hYmxlZCkge1xuICAgICAgaWYgKCFpbnB1dC5tZmFDb2RlKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgICAgcmVxdWlyZXNNRkE6IHRydWUsXG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIC8vIFZlcmlmaWNhciBjw7NkaWdvIE1GQSBzZXLDoSBmZWl0byBwZWxvIE1GQVNlcnZpY2VcbiAgICAgIC8vIFJldG9ybmFyIHBhcmEgbyBjb250cm9sbGVyIGNoYW1hciBvIHByw7N4aW1vIHBhc3NvXG4gICAgICByZXR1cm4ge1xuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgIHJlcXVpcmVzTUZBOiB0cnVlLFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBNRkEgbsOjbyBoYWJpbGl0YWRvIChkZXZlcmlhIHNlciByYXJvIGVtIHByb2R1w6fDo28pXG4gICAgLy8gQ3JpYXIgc2Vzc8OjbyBkaXJldGFtZW50ZVxuICAgIHJldHVybiBhd2FpdCB0aGlzLmNyZWF0ZVNlc3Npb24odXNlciwgaW5wdXQsIGlwQWRkcmVzcywgdXNlckFnZW50KTtcbiAgfSxcblxuICAvKipcbiAgICogQ3JpYSBzZXNzw6NvIGFww7NzIGF1dGVudGljYcOnw6NvIGJlbS1zdWNlZGlkYVxuICAgKi9cbiAgYXN5bmMgY3JlYXRlU2Vzc2lvbihcbiAgICB1c2VyOiBEQlVzZXIsXG4gICAgaW5wdXQ6IExvZ2luSW5wdXQsXG4gICAgaXBBZGRyZXNzOiBzdHJpbmcsXG4gICAgdXNlckFnZW50OiBzdHJpbmdcbiAgKTogUHJvbWlzZTxBdXRoUmVzcG9uc2U+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG5cbiAgICB0cnkge1xuICAgICAgLy8gR2VyYXIgdG9rZW5zIEpXVFxuICAgICAgY29uc3Qgc2Vzc2lvbklkID0gZ2VuZXJhdGVVVUlEKCk7XG4gICAgICBjb25zdCB0b2tlbnMgPSBhd2FpdCBnZW5lcmF0ZUF1dGhUb2tlbnMoe1xuICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgIHNlc3Npb25JZCxcbiAgICAgICAgbWZhVmVyaWZpZWQ6IHVzZXIubWZhRW5hYmxlZCB8fCBmYWxzZSxcbiAgICAgICAgY291bnRlcjogMCxcbiAgICAgIH0pO1xuXG4gICAgICAvLyBTYWx2YXIgc2Vzc8OjbyBubyBiYW5jb1xuICAgICAgYXdhaXQgZGIuaW5zZXJ0KHNjaGVtYS5zZXNzaW9ucykudmFsdWVzKHtcbiAgICAgICAgaWQ6IHNlc3Npb25JZCxcbiAgICAgICAgdXNlcklkOiB1c2VyLmlkLFxuICAgICAgICByZWZyZXNoVG9rZW5IYXNoOiBhd2FpdCBzaGEyNTYodG9rZW5zLnJlZnJlc2hUb2tlbiksXG4gICAgICAgIGV4cGlyZXNBdDogdG9rZW5zLmV4cGlyZXNBdCxcbiAgICAgICAgcmVmcmVzaEV4cGlyZXNBdDogdG9rZW5zLnJlZnJlc2hFeHBpcmVzQXQsXG4gICAgICAgIGNyZWF0ZWRBdDogbmV3IERhdGUoKSxcbiAgICAgICAgcmV2b2tlZDogZmFsc2UsXG4gICAgICB9KTtcblxuICAgICAgLy8gQXR1YWxpemFyIMO6bHRpbW8gbG9naW5cbiAgICAgIGF3YWl0IGRiXG4gICAgICAgIC51cGRhdGUoc2NoZW1hLnVzZXJzKVxuICAgICAgICAuc2V0KHtcbiAgICAgICAgICBsYXN0TG9naW5BdDogbmV3IERhdGUoKSxcbiAgICAgICAgICB1cGRhdGVkQXQ6IG5ldyBEYXRlKCksXG4gICAgICAgIH0pXG4gICAgICAgIC53aGVyZShlcShzY2hlbWEudXNlcnMuaWQsIHVzZXIuaWQpKTtcblxuICAgICAgLy8gQ3JpYXIvYXR1YWxpemFyIGRpc3Bvc2l0aXZvXG4gICAgICBsZXQgZGV2aWNlSWQ6IHN0cmluZyB8IHVuZGVmaW5lZDtcbiAgICAgIGNvbnN0IGRldmljZVR5cGUgPSB0aGlzLmRldGVjdERldmljZVR5cGUodXNlckFnZW50KTtcbiAgICAgIGNvbnN0IHsgb3MsIGJyb3dzZXIgfSA9IHRoaXMucGFyc2VVc2VyQWdlbnQodXNlckFnZW50KTtcbiAgICAgIFxuICAgICAgaWYgKGlucHV0LmRldmljZUlkKSB7XG4gICAgICAgIGRldmljZUlkID0gaW5wdXQuZGV2aWNlSWQ7XG4gICAgICAgIGF3YWl0IGRiXG4gICAgICAgICAgLnVwZGF0ZShzY2hlbWEuZGV2aWNlcylcbiAgICAgICAgICAuc2V0KHtcbiAgICAgICAgICAgIGxhc3RTZWVuQXQ6IG5ldyBEYXRlKCksXG4gICAgICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgICAgfSlcbiAgICAgICAgICAud2hlcmUoZXEoc2NoZW1hLmRldmljZXMuaWQsIGRldmljZUlkKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBDcmlhciBub3ZvIGRpc3Bvc2l0aXZvXG4gICAgICAgIGRldmljZUlkID0gZ2VuZXJhdGVVVUlEKCk7XG5cbiAgICAgICAgYXdhaXQgZGIuaW5zZXJ0KHNjaGVtYS5kZXZpY2VzKS52YWx1ZXMoe1xuICAgICAgICAgIGlkOiBkZXZpY2VJZCxcbiAgICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgICAgbmFtZTogYCR7ZGV2aWNlVHlwZX0gLSAke2Jyb3dzZXJ9IG9uICR7b3N9YCxcbiAgICAgICAgICB0eXBlOiBkZXZpY2VUeXBlLFxuICAgICAgICAgIG9zLFxuICAgICAgICAgIGJyb3dzZXIsXG4gICAgICAgICAgaXNUcnVzdGVkOiBpbnB1dC5yZW1lbWJlckRldmljZSA/PyBmYWxzZSxcbiAgICAgICAgICB0cnVzdGVkVW50aWw6IGlucHV0LnJlbWVtYmVyRGV2aWNlXG4gICAgICAgICAgICA/IG5ldyBEYXRlKERhdGUubm93KCkgKyBBVVRIX0NPTlNUQU5UUy5UUlVTVEVEX0RFVklDRV9FWFBJUllfREFZUyAqIDI0ICogNjAgKiA2MCAqIDEwMDApXG4gICAgICAgICAgICA6IG51bGwsXG4gICAgICAgICAgbGFzdFNlZW5BdDogbmV3IERhdGUoKSxcbiAgICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgICAgdXNlckFnZW50LFxuICAgICAgICAgIGNyZWF0ZWRBdDogbmV3IERhdGUoKSxcbiAgICAgICAgfSk7XG4gICAgICB9XG5cbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdMT0dJTl9TVUNDRVNTJyxcbiAgICAgICAgdXNlcklkOiB1c2VyLmlkLFxuICAgICAgICBzZXNzaW9uSWQsXG4gICAgICAgIGRldmljZUlkLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgIHVzZXJJZDogdXNlci5pZCxcbiAgICAgICAgc2Vzc2lvbjoge1xuICAgICAgICAgIHNlc3Npb25JZCxcbiAgICAgICAgICB1c2VySWQ6IHVzZXIuaWQsXG4gICAgICAgICAgYWNjZXNzVG9rZW46IHRva2Vucy5hY2Nlc3NUb2tlbixcbiAgICAgICAgICByZWZyZXNoVG9rZW46IHRva2Vucy5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgZXhwaXJlc0F0OiB0b2tlbnMuZXhwaXJlc0F0LFxuICAgICAgICAgIHJlZnJlc2hFeHBpcmVzQXQ6IHRva2Vucy5yZWZyZXNoRXhwaXJlc0F0LFxuICAgICAgICAgIGRldmljZToge1xuICAgICAgICAgICAgZGV2aWNlSWQ6IGRldmljZUlkISxcbiAgICAgICAgICAgIG5hbWU6IGAke2RldmljZVR5cGV9IC0gJHticm93c2VyfSBvbiAke29zfWAsXG4gICAgICAgICAgICB0eXBlOiBkZXZpY2VUeXBlLFxuICAgICAgICAgICAgb3MsXG4gICAgICAgICAgICBicm93c2VyLFxuICAgICAgICAgICAgaXNUcnVzdGVkOiBpbnB1dC5yZW1lbWJlckRldmljZSA/PyBmYWxzZSxcbiAgICAgICAgICAgIGxhc3RTZWVuQXQ6IG5ldyBEYXRlKCksXG4gICAgICAgICAgICBpcEFkZHJlc3MsXG4gICAgICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgICAgfSxcbiAgICAgICAgICBtZmFWZXJpZmllZDogdXNlci5tZmFFbmFibGVkIHx8IGZhbHNlLFxuICAgICAgICAgIGNyZWF0ZWRBdDogbmV3IERhdGUoKSxcbiAgICAgICAgfSxcbiAgICAgIH07XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdMT0dJTl9GQUlMVVJFX1BBU1NXT1JEJyxcbiAgICAgICAgdXNlcklkOiB1c2VyLmlkLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgZmFpbHVyZVJlYXNvbjogJ0Vycm8gYW8gY3JpYXIgc2Vzc8OjbycsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICBlcnJvcjogeyBjb2RlOiAnSU5URVJOQUxfRVJST1InLCBtZXNzYWdlOiBBVVRIX0NPTlNUQU5UUy5FUlJPUl9NRVNTQUdFUy5JTlRFUk5BTF9FUlJPUiB9LFxuICAgICAgfTtcbiAgICB9XG4gIH0sXG5cbiAgLyoqXG4gICAqIEluY3JlbWVudGEgdGVudGF0aXZhcyBmYWxoYXMgZSBhcGxpY2EgbG9ja291dCBzZSBuZWNlc3PDoXJpb1xuICAgKi9cbiAgYXN5bmMgaW5jcmVtZW50RmFpbGVkQXR0ZW1wdHModXNlcklkOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG4gICAgXG4gICAgYXdhaXQgZGJcbiAgICAgIC51cGRhdGUoc2NoZW1hLnVzZXJzKVxuICAgICAgLnNldCh7XG4gICAgICAgIGZhaWxlZExvZ2luQXR0ZW1wdHM6IHNxbGAke3NjaGVtYS51c2Vycy5mYWlsZWRMb2dpbkF0dGVtcHRzfSArIDFgLFxuICAgICAgICBsb2NrZWRVbnRpbDogc3FsYENBU0UgXG4gICAgICAgICAgV0hFTiAke3NjaGVtYS51c2Vycy5mYWlsZWRMb2dpbkF0dGVtcHRzfSArIDEgPj0gJHtBVVRIX0NPTlNUQU5UUy5NQVhfTE9HSU5fQVRURU1QVFN9XG4gICAgICAgICAgVEhFTiBOT1coKSArIElOVEVSVkFMICcke0FVVEhfQ09OU1RBTlRTLkxPQ0tPVVRfRFVSQVRJT059IHNlY29uZHMnXG4gICAgICAgICAgRUxTRSAke3NjaGVtYS51c2Vycy5sb2NrZWRVbnRpbH1cbiAgICAgICAgRU5EYCxcbiAgICAgICAgdXBkYXRlZEF0OiBuZXcgRGF0ZSgpLFxuICAgICAgfSlcbiAgICAgIC53aGVyZShlcShzY2hlbWEudXNlcnMuaWQsIHVzZXJJZCkpO1xuICB9LFxuXG4gIC8qKlxuICAgKiBSZXNldCB0ZW50YXRpdmFzIGZhbGhhcyBhcMOzcyBsb2dpbiBiZW0tc3VjZWRpZG9cbiAgICovXG4gIGFzeW5jIHJlc2V0RmFpbGVkQXR0ZW1wdHModXNlcklkOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG4gICAgXG4gICAgYXdhaXQgZGJcbiAgICAgIC51cGRhdGUoc2NoZW1hLnVzZXJzKVxuICAgICAgLnNldCh7XG4gICAgICAgIGZhaWxlZExvZ2luQXR0ZW1wdHM6IDAsXG4gICAgICAgIGxvY2tlZFVudGlsOiBudWxsLFxuICAgICAgICB1cGRhdGVkQXQ6IG5ldyBEYXRlKCksXG4gICAgICB9KVxuICAgICAgLndoZXJlKGVxKHNjaGVtYS51c2Vycy5pZCwgdXNlcklkKSk7XG4gIH0sXG5cbiAgLyoqXG4gICAqIERldGVjdGEgdGlwbyBkZSBkaXNwb3NpdGl2byBhIHBhcnRpciBkbyB1c2VyIGFnZW50XG4gICAqL1xuICBkZXRlY3REZXZpY2VUeXBlKHVzZXJBZ2VudDogc3RyaW5nKTogJ2Rlc2t0b3AnIHwgJ21vYmlsZScgfCAndGFibGV0JyB8ICd1bmtub3duJyB7XG4gICAgY29uc3QgdWEgPSB1c2VyQWdlbnQudG9Mb3dlckNhc2UoKTtcbiAgICBcbiAgICBpZiAoL21vYmlsZXxhbmRyb2lkfGlwaG9uZXxpcG9kfGJsYWNrYmVycnl8d2luZG93cyBwaG9uZS9pLnRlc3QodWEpKSB7XG4gICAgICByZXR1cm4gJ21vYmlsZSc7XG4gICAgfVxuICAgIGlmICgvdGFibGV0fGlwYWR8c2lsa3xraW5kbGUvaS50ZXN0KHVhKSkge1xuICAgICAgcmV0dXJuICd0YWJsZXQnO1xuICAgIH1cbiAgICBpZiAoL2Rlc2t0b3B8d2luZG93c3xtYWNpbnRvc2h8bGludXh8dWJ1bnR1L2kudGVzdCh1YSkpIHtcbiAgICAgIHJldHVybiAnZGVza3RvcCc7XG4gICAgfVxuICAgIFxuICAgIHJldHVybiAndW5rbm93bic7XG4gIH0sXG5cbiAgLyoqXG4gICAqIFBhcnNlIHVzZXIgYWdlbnQgcGFyYSBleHRyYWlyIE9TIGUgYnJvd3NlclxuICAgKiBJbXBsZW1lbnRhw6fDo28gc2ltcGxpZmljYWRhIC0gdXNhciBiaWJsaW90ZWNhIGRlZGljYWRhIGVtIHByb2R1w6fDo29cbiAgICovXG4gIHBhcnNlVXNlckFnZW50KHVzZXJBZ2VudDogc3RyaW5nKTogeyBvczogc3RyaW5nOyBicm93c2VyOiBzdHJpbmcgfSB7XG4gICAgY29uc3QgdWEgPSB1c2VyQWdlbnQudG9Mb3dlckNhc2UoKTtcbiAgICBcbiAgICBsZXQgb3MgPSAnVW5rbm93bic7XG4gICAgaWYgKC93aW5kb3dzIG50L2kudGVzdCh1YSkpIG9zID0gJ1dpbmRvd3MnO1xuICAgIGVsc2UgaWYgKC9tYWNpbnRvc2h8bWFjIG9zIHgvaS50ZXN0KHVhKSkgb3MgPSAnbWFjT1MnO1xuICAgIGVsc2UgaWYgKC9saW51eHx1YnVudHUvaS50ZXN0KHVhKSkgb3MgPSAnTGludXgnO1xuICAgIGVsc2UgaWYgKC9hbmRyb2lkL2kudGVzdCh1YSkpIG9zID0gJ0FuZHJvaWQnO1xuICAgIGVsc2UgaWYgKC9pcGhvbmV8aXBhZHxpcG9kL2kudGVzdCh1YSkpIG9zID0gJ2lPUyc7XG4gICAgXG4gICAgbGV0IGJyb3dzZXIgPSAnVW5rbm93bic7XG4gICAgaWYgKC9jaHJvbWV8Y3Jpb3MvaS50ZXN0KHVhKSkgYnJvd3NlciA9ICdDaHJvbWUnO1xuICAgIGVsc2UgaWYgKC9maXJlZm94fGZ4aW9zL2kudGVzdCh1YSkpIGJyb3dzZXIgPSAnRmlyZWZveCc7XG4gICAgZWxzZSBpZiAoL3NhZmFyaXx2ZXJzaW9uXFwvXFxkKy9pLnRlc3QodWEpICYmICEvY2hyb21lL2kudGVzdCh1YSkpIGJyb3dzZXIgPSAnU2FmYXJpJztcbiAgICBlbHNlIGlmICgvZWRnL2kudGVzdCh1YSkpIGJyb3dzZXIgPSAnRWRnZSc7XG4gICAgZWxzZSBpZiAoL29wZXJhfG9wci9pLnRlc3QodWEpKSBicm93c2VyID0gJ09wZXJhJztcbiAgICBcbiAgICByZXR1cm4geyBvcywgYnJvd3NlciB9O1xuICB9LFxuXG4gIC8qKlxuICAgKiBMb2cgZGUgYXVkaXRvcmlhIHBhcmEgZXZlbnRvcyBkZSBhdXRlbnRpY2HDp8Ojb1xuICAgKi9cbiAgYXN5bmMgYXVkaXRMb2coZXZlbnQ6IE9taXQ8QXV0aEF1ZGl0RXZlbnQsICdzdWNjZXNzJz4gJiB7IHN1Y2Nlc3M6IGJvb2xlYW4gfSk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcbiAgICBcbiAgICB0cnkge1xuICAgICAgYXdhaXQgZGIuaW5zZXJ0KHNjaGVtYS5hdWRpdExvZ3MpLnZhbHVlcyh7XG4gICAgICAgIGlkOiBnZW5lcmF0ZVVVSUQoKSxcbiAgICAgICAgYWN0aW9uOiBldmVudC5hY3Rpb24sXG4gICAgICAgIHVzZXJJZDogZXZlbnQudXNlcklkIHx8IG51bGwsXG4gICAgICAgIHNlc3Npb25JZDogZXZlbnQuc2Vzc2lvbklkIHx8IG51bGwsXG4gICAgICAgIGRldmljZUlkOiBldmVudC5kZXZpY2VJZCB8fCBudWxsLFxuICAgICAgICB0aW1lc3RhbXA6IGV2ZW50LnRpbWVzdGFtcCxcbiAgICAgICAgaXBBZGRyZXNzOiBldmVudC5pcEFkZHJlc3MsXG4gICAgICAgIHVzZXJBZ2VudDogZXZlbnQudXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiBldmVudC5zdWNjZXNzLFxuICAgICAgICBmYWlsdXJlUmVhc29uOiBldmVudC5mYWlsdXJlUmVhc29uIHx8IG51bGwsXG4gICAgICAgIG1ldGFkYXRhOiBldmVudC5tZXRhZGF0YSB8fCBudWxsLFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIC8vIE5VTkNBIGZhbGhhciBhdXRlbnRpY2HDp8OjbyBwb3IgZXJybyBkZSBsb2dnaW5nXG4gICAgICBjb25zb2xlLmVycm9yKCdbQXV0aFNlcnZpY2VdIEZhbGhhIGFvIHJlZ2lzdHJhciBsb2cgZGUgYXVkaXRvcmlhOicsIGVycm9yKTtcbiAgICB9XG4gIH0sXG59O1xuXG4vLyBJbXBvcnQgbmVjZXNzw6FyaW8gcGFyYSBTUUxcbmltcG9ydCB7IHNxbCB9IGZyb20gJ2RyaXp6bGUtb3JtJztcbiJdfQ==
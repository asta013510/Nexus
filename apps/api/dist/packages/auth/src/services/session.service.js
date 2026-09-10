/**
 * Serviço de Gerenciamento de Sessão
 *
 * Responsabilidades:
 * - Validação de tokens JWT
 * - Refresh de access tokens
 * - Revogação de sessões
 * - Validação de dispositivos confiáveis
 * - Auditoria de eventos de sessão
 *
 * SECURITY NOTES:
 * - Access tokens com vida curta (15 min)
 * - Refresh tokens com rotação
 * - Validação de assinatura JWT
 * - Verificação de revogação no banco
 * - Binding entre sessão e dispositivo
 */
import { eq, and } from 'drizzle-orm';
import { sha256, verifyJWT } from '@zero/crypto';
import { schema } from '@zero/database';
import { generateUUID } from '@zero/shared';
import { AUTH_CONSTANTS } from '../constants';
import { generateAuthTokens } from '../utils/tokens';
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
export const SessionService = {
    /**
     * Valida access token JWT
     */
    async validateAccessToken(accessToken) {
        try {
            const result = await verifyJWT(accessToken);
            if (!result.valid || !result.payload) {
                return { valid: false, error: 'Token inválido ou expirado' };
            }
            const payload = result.payload;
            // Verificar tipo do token
            if (payload.typ !== 'access') {
                return { valid: false, error: 'Tipo de token incorreto' };
            }
            // Verificar se sessão existe e não foi revogada
            const db = getDB();
            const sessions = await db
                .select({ revoked: schema.sessions.revoked })
                .from(schema.sessions)
                .where(eq(schema.sessions.id, payload.sid))
                .limit(1);
            if (!sessions || sessions.length === 0) {
                return { valid: false, error: 'Sessão não encontrada' };
            }
            if (sessions[0].revoked) {
                return { valid: false, error: 'Sessão revogada' };
            }
            return { valid: true, payload };
        }
        catch (error) {
            console.error('Erro ao validar access token:', error);
            return { valid: false, error: 'Erro ao validar token' };
        }
    },
    /**
     * Realiza refresh do access token usando refresh token
     * Implementa rotação de refresh tokens para segurança
     */
    async refreshAccessToken(refreshToken, ipAddress, userAgent) {
        const db = getDB();
        try {
            // Verificar refresh token
            const jwtResult = await verifyJWT(refreshToken);
            if (!jwtResult.valid || !jwtResult.payload) {
                return { success: false, error: { code: 'INVALID_TOKEN', message: 'Refresh token inválido ou expirado' } };
            }
            const payload = jwtResult.payload;
            // Verificar tipo
            if (payload.typ !== 'refresh') {
                return { success: false, error: { code: 'INVALID_TOKEN_TYPE', message: 'Tipo de token incorreto' } };
            }
            // Buscar sessão
            const sessions = await db
                .select()
                .from(schema.sessions)
                .where(and(eq(schema.sessions.id, payload.sid), eq(schema.sessions.revoked, false)))
                .limit(1);
            if (!sessions || sessions.length === 0) {
                return { success: false, error: { code: 'SESSION_NOT_FOUND', message: 'Sessão não encontrada ou revogada' } };
            }
            const session = sessions[0];
            // Verificar expiry
            if (new Date(session.refreshExpiresAt) < new Date()) {
                // Sessão expirada, revogar
                await db
                    .update(schema.sessions)
                    .set({ revoked: true })
                    .where(eq(schema.sessions.id, session.id));
                return { success: false, error: { code: 'SESSION_EXPIRED', message: 'Sessão expirada' } };
            }
            // Verificar hash do refresh token (detecção de roubo/replay)
            const incomingHash = await sha256(refreshToken);
            // Se o hash não bater, pode indicar token roubado sendo usado por atacante
            // Em produção: invalidar TODAS as sessões do usuário
            if (session.refreshTokenHash !== incomingHash) {
                console.warn('Possível ataque de replay detectado - refresh token mismatch');
                // Revogar todas as sessões do usuário como medida de segurança
                await db
                    .update(schema.sessions)
                    .set({ revoked: true })
                    .where(eq(schema.sessions.userId, payload.sub));
                // Auditoria de segurança
                await this.auditLog({
                    action: 'TOKEN_REFRESH_FAILURE',
                    userId: payload.sub,
                    sessionId: payload.sid,
                    timestamp: new Date(),
                    ipAddress,
                    userAgent,
                    success: false,
                    failureReason: 'Possible replay attack detected - refresh token mismatch',
                });
                return {
                    success: false,
                    error: { code: 'SECURITY_VIOLATION', message: 'Violação de segurança detectada. Todas as sessões foram revogadas.' }
                };
            }
            // Gerar novos tokens (rotação)
            const newTokens = await generateAuthTokens({
                userId: payload.sub,
                sessionId: payload.sid,
                mfaVerified: true, // Assumindo que já foi verificado no login
                counter: payload.counter + 1,
            });
            // Atualizar sessão com novo refresh token hash
            await db
                .update(schema.sessions)
                .set({
                refreshTokenHash: await sha256(newTokens.refreshToken),
                expiresAt: newTokens.expiresAt,
                refreshExpiresAt: newTokens.refreshExpiresAt,
            })
                .where(eq(schema.sessions.id, session.id));
            // Buscar dados do dispositivo
            const devices = await db
                .select()
                .from(schema.devices)
                .where(eq(schema.devices.userId, payload.sub))
                .limit(1);
            const device = devices && devices.length > 0 ? devices[0] : undefined;
            const sessionData = {
                sessionId: payload.sid,
                userId: payload.sub,
                accessToken: newTokens.accessToken,
                refreshToken: newTokens.refreshToken,
                expiresAt: newTokens.expiresAt,
                refreshExpiresAt: newTokens.refreshExpiresAt,
                device: device ? {
                    deviceId: device.id,
                    name: device.name,
                    type: device.type,
                    os: device.os || '',
                    browser: device.browser || '',
                    isTrusted: device.isTrusted,
                    lastSeenAt: device.lastSeenAt,
                    ipAddress: device.ipAddress || undefined,
                    userAgent: device.userAgent || undefined,
                } : undefined,
                mfaVerified: true,
                createdAt: session.createdAt,
            };
            // Auditoria
            await this.auditLog({
                action: 'TOKEN_REFRESH_SUCCESS',
                userId: payload.sub,
                sessionId: payload.sid,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: true,
            });
            return { success: true, session: sessionData };
        }
        catch (error) {
            console.error('Erro ao refresh access token:', error);
            return { success: false, error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR } };
        }
    },
    /**
     * Revoga uma sessão específica
     */
    async revokeSession(sessionId, userId, ipAddress, userAgent) {
        const db = getDB();
        try {
            // Verificar ownership da sessão
            const sessions = await db
                .select()
                .from(schema.sessions)
                .where(and(eq(schema.sessions.id, sessionId), eq(schema.sessions.userId, userId)))
                .limit(1);
            if (!sessions || sessions.length === 0) {
                return { success: false, error: { code: 'SESSION_NOT_FOUND', message: 'Sessão não encontrada' } };
            }
            // Revogar sessão
            await db
                .update(schema.sessions)
                .set({ revoked: true })
                .where(eq(schema.sessions.id, sessionId));
            // Auditoria
            await this.auditLog({
                action: 'SESSION_REVOKED',
                userId,
                sessionId,
                timestamp: new Date(),
                ipAddress,
                userAgent,
                success: true,
            });
            return { success: true };
        }
        catch (error) {
            console.error('Erro ao revogar sessão:', error);
            return { success: false, error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR } };
        }
    },
    /**
     * Revoga TODAS as sessões de um usuário (logout em todos os dispositivos)
     */
    async revokeAllSessions(userId, exceptSessionId, ipAddress, userAgent) {
        const db = getDB();
        try {
            const updateQuery = db
                .update(schema.sessions)
                .set({ revoked: true })
                .where(and(eq(schema.sessions.userId, userId), exceptSessionId ? eq(schema.sessions.revoked, false) : undefined));
            // Se exceto uma sessão, adicionar condição
            if (exceptSessionId) {
                await db
                    .update(schema.sessions)
                    .set({ revoked: true })
                    .where(and(eq(schema.sessions.userId, userId), sql `${schema.sessions.id} != ${exceptSessionId}`));
            }
            else {
                await updateQuery;
            }
            // Auditoria
            await this.auditLog({
                action: 'SESSION_REVOKED',
                userId,
                timestamp: new Date(),
                ipAddress: ipAddress || '',
                userAgent: userAgent || '',
                success: true,
                metadata: { allSessions: true, exceptSessionId },
            });
            return { success: true };
        }
        catch (error) {
            console.error('Erro ao revogar todas as sessões:', error);
            return { success: false, error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR } };
        }
    },
    /**
     * Logout - revoga sessão atual
     */
    async logout(sessionId, userId, ipAddress, userAgent) {
        return await this.revokeSession(sessionId, userId, ipAddress, userAgent);
    },
    /**
     * Lista sessões ativas de um usuário
     */
    async listActiveSessions(userId) {
        const db = getDB();
        try {
            const sessions = await db
                .select({
                sessionId: schema.sessions.id,
                createdAt: schema.sessions.createdAt,
                expiresAt: schema.sessions.expiresAt,
                refreshExpiresAt: schema.sessions.refreshExpiresAt,
                deviceName: schema.devices.name,
                deviceType: schema.devices.type,
                deviceOS: schema.devices.os,
                deviceBrowser: schema.devices.browser,
                deviceIsTrusted: schema.devices.isTrusted,
                deviceLastSeenAt: schema.devices.lastSeenAt,
                deviceIpAddress: schema.devices.ipAddress,
            })
                .from(schema.sessions)
                .leftJoin(schema.devices, eq(schema.sessions.id, schema.devices.userId))
                .where(and(eq(schema.sessions.userId, userId), eq(schema.sessions.revoked, false)));
            return {
                success: true,
                sessions: sessions.map((s) => ({
                    sessionId: s.sessionId,
                    createdAt: s.createdAt,
                    expiresAt: s.expiresAt,
                    device: {
                        name: s.deviceName,
                        type: s.deviceType,
                        os: s.deviceOS,
                        browser: s.deviceBrowser,
                        isTrusted: s.deviceIsTrusted,
                        lastSeenAt: s.deviceLastSeenAt,
                        ipAddress: s.deviceIpAddress,
                    },
                }))
            };
        }
        catch (error) {
            console.error('Erro ao listar sessões:', error);
            return { success: false, error: { code: 'INTERNAL_ERROR', message: AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR } };
        }
    },
    /**
     * Verifica se dispositivo é confiável
     */
    async isTrustedDevice(userId, deviceId) {
        const db = getDB();
        try {
            const devices = await db
                .select({ isTrusted: schema.devices.isTrusted, trustedUntil: schema.devices.trustedUntil })
                .from(schema.devices)
                .where(and(eq(schema.devices.id, deviceId), eq(schema.devices.userId, userId)))
                .limit(1);
            if (!devices || devices.length === 0) {
                return false;
            }
            const device = devices[0];
            if (!device.isTrusted) {
                return false;
            }
            // Verificar se trust ainda válido
            if (device.trustedUntil && new Date(device.trustedUntil) < new Date()) {
                return false;
            }
            return true;
        }
        catch (error) {
            console.error('Erro ao verificar dispositivo confiável:', error);
            return false;
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
// Helper para SQL (importar de drizzle-orm)
const sql = {
    not: (value) => value,
    ne: (col, val) => ({ col, val, op: '!=' }),
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2Vzc2lvbi5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vLi4vLi4vLi4vcGFja2FnZXMvYXV0aC9zcmMvc2VydmljZXMvc2Vzc2lvbi5zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7Ozs7Ozs7Ozs7Ozs7O0dBZ0JHO0FBRUgsT0FBTyxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsTUFBTSxhQUFhLENBQUM7QUFDdEMsT0FBTyxFQUFFLE1BQU0sRUFBRSxTQUFTLEVBQUUsTUFBTSxjQUFjLENBQUM7QUFDakQsT0FBTyxFQUFFLE1BQU0sRUFBRSxNQUFNLGdCQUFnQixDQUFDO0FBQ3hDLE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxjQUFjLENBQUM7QUFDNUMsT0FBTyxFQUFFLGNBQWMsRUFBRSxNQUFNLGNBQWMsQ0FBQztBQUU5QyxPQUFPLEVBQUUsa0JBQWtCLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUVyRCxJQUFJLFFBQVEsR0FBUSxJQUFJLENBQUM7QUFFekIsTUFBTSxVQUFVLGlCQUFpQixDQUFDLE1BQVc7SUFDM0MsUUFBUSxHQUFHLE1BQU0sQ0FBQztBQUNwQixDQUFDO0FBRUQsU0FBUyxLQUFLO0lBQ1osSUFBSSxDQUFDLFFBQVEsRUFBRSxDQUFDO1FBQ2QsTUFBTSxJQUFJLEtBQUssQ0FBQyxrQ0FBa0MsQ0FBQyxDQUFDO0lBQ3RELENBQUM7SUFDRCxPQUFPLFFBQVEsQ0FBQztBQUNsQixDQUFDO0FBRUQsTUFBTSxDQUFDLE1BQU0sY0FBYyxHQUFHO0lBQzVCOztPQUVHO0lBQ0gsS0FBSyxDQUFDLG1CQUFtQixDQUFDLFdBQW1CO1FBQzNDLElBQUksQ0FBQztZQUNILE1BQU0sTUFBTSxHQUFHLE1BQU0sU0FBUyxDQUFDLFdBQVcsQ0FBQyxDQUFDO1lBRTVDLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSxDQUFDO2dCQUNy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Q0FBQyxTQUFTLElBQUksSUFBSTtnQkFDbEMsUUFBUSxFQUFFLEtBQUssQ0FBQyxRQUFRLElBQUksSUFBSTtnQkFDaEMsU0FBUyxFQUFFLEtBQUssQ0FBQyxTQUFTO2dCQUMxQixTQUFTLEVBQUUsS0FBSyxDQUFDLFNBQVM7Z0JBQzFCLFNBQVMsRUFBRSxLQUFLLENBQUMsU0FBUztnQkFDMUIsT0FBTyxFQUFFLEtBQUssQ0FBQyxPQUFPO2dCQUN0QixhQUFhLEVBQUUsS0FBSyxDQUFDLGFBQWEsSUFBSSxJQUFJO2dCQUMxQyxRQUFRLEVBQUUsS0FBSyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUk7YUFDakUsQ0FBQyxDQUFDO1FBQ0wsQ0FBQztRQUFDLE9BQU8sS0FBSyxFQUFFLENBQUM7WUFDZixPQUFPLENBQUMsS0FBSyxDQUFDLGlDQUFpQyxFQUFFLEtBQUssQ0FBQyxDQUFDO1FBQzFELENBQUM7SUFDSCxDQUFDO0NBQ0YsQ0FBQztBQUVGLDRDQUE0QztBQUM1QyxNQUFNLEdBQUcsR0FBRztJQUNWLEdBQUcsRUFBRSxDQUFDLEtBQVUsRUFBRSxFQUFFLENBQUMsS0FBSztJQUMxQixFQUFFLEVBQUUsQ0FBQyxHQUFRLEVBQUUsR0FBUSxFQUFFLEVBQUUsQ0FBQyxDQUFDLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsSUFBSSxFQUFFLENBQUM7Q0FDckQsQ0FBQyIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogU2VydmnDp28gZGUgR2VyZW5jaWFtZW50byBkZSBTZXNzw6NvXG4gKiBcbiAqIFJlc3BvbnNhYmlsaWRhZGVzOlxuICogLSBWYWxpZGHDp8OjbyBkZSB0b2tlbnMgSldUXG4gKiAtIFJlZnJlc2ggZGUgYWNjZXNzIHRva2Vuc1xuICogLSBSZXZvZ2HDp8OjbyBkZSBzZXNzw7Vlc1xuICogLSBWYWxpZGHDp8OjbyBkZSBkaXNwb3NpdGl2b3MgY29uZmnDoXZlaXNcbiAqIC0gQXVkaXRvcmlhIGRlIGV2ZW50b3MgZGUgc2Vzc8Ojb1xuICogXG4gKiBTRUNVUklUWSBOT1RFUzpcbiAqIC0gQWNjZXNzIHRva2VucyBjb20gdmlkYSBjdXJ0YSAoMTUgbWluKVxuICogLSBSZWZyZXNoIHRva2VucyBjb20gcm90YcOnw6NvXG4gKiAtIFZhbGlkYcOnw6NvIGRlIGFzc2luYXR1cmEgSldUXG4gKiAtIFZlcmlmaWNhw6fDo28gZGUgcmV2b2dhw6fDo28gbm8gYmFuY29cbiAqIC0gQmluZGluZyBlbnRyZSBzZXNzw6NvIGUgZGlzcG9zaXRpdm9cbiAqL1xuXG5pbXBvcnQgeyBlcSwgYW5kIH0gZnJvbSAnZHJpenpsZS1vcm0nO1xuaW1wb3J0IHsgc2hhMjU2LCB2ZXJpZnlKV1QgfSBmcm9tICdAemVyby9jcnlwdG8nO1xuaW1wb3J0IHsgc2NoZW1hIH0gZnJvbSAnQHplcm8vZGF0YWJhc2UnO1xuaW1wb3J0IHsgZ2VuZXJhdGVVVUlEIH0gZnJvbSAnQHplcm8vc2hhcmVkJztcbmltcG9ydCB7IEFVVEhfQ09OU1RBTlRTIH0gZnJvbSAnLi4vY29uc3RhbnRzJztcbmltcG9ydCB0eXBlIHsgU2Vzc2lvbkRhdGEsIEpXVFBheWxvYWQsIFJlZnJlc2hUb2tlblBheWxvYWQsIEF1dGhBdWRpdEV2ZW50IH0gZnJvbSAnLi4vdHlwZXMnO1xuaW1wb3J0IHsgZ2VuZXJhdGVBdXRoVG9rZW5zIH0gZnJvbSAnLi4vdXRpbHMvdG9rZW5zJztcblxubGV0IGRiQ2xpZW50OiBhbnkgPSBudWxsO1xuXG5leHBvcnQgZnVuY3Rpb24gc2V0RGF0YWJhc2VDbGllbnQoY2xpZW50OiBhbnkpOiB2b2lkIHtcbiAgZGJDbGllbnQgPSBjbGllbnQ7XG59XG5cbmZ1bmN0aW9uIGdldERCKCkge1xuICBpZiAoIWRiQ2xpZW50KSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdEYXRhYmFzZSBjbGllbnQgbsOjbyBpbmljaWFsaXphZG8nKTtcbiAgfVxuICByZXR1cm4gZGJDbGllbnQ7XG59XG5cbmV4cG9ydCBjb25zdCBTZXNzaW9uU2VydmljZSA9IHtcbiAgLyoqXG4gICAqIFZhbGlkYSBhY2Nlc3MgdG9rZW4gSldUXG4gICAqL1xuICBhc3luYyB2YWxpZGF0ZUFjY2Vzc1Rva2VuKGFjY2Vzc1Rva2VuOiBzdHJpbmcpOiBQcm9taXNlPHsgdmFsaWQ6IGJvb2xlYW47IHBheWxvYWQ/OiBKV1RQYXlsb2FkOyBlcnJvcj86IHN0cmluZyB9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHZlcmlmeUpXVChhY2Nlc3NUb2tlbik7XG4gICAgICBcbiAgICAgIGlmICghcmVzdWx0LnZhbGlkIHx8ICFyZXN1bHQucGF5bG9hZCkge1xuICAgICAgICByZXR1cm4geyB2YWxpZDogZmFsc2UsIGVycm9yOiAnVG9rZW4gaW52w6FsaWRvIG91IGV4cGlyYWRvJyB9O1xuICAgICAgfVxuXG4gICAgICBjb25zdCBwYXlsb2FkID0gcmVzdWx0LnBheWxvYWQgYXMgSldUUGF5bG9hZDtcblxuICAgICAgLy8gVmVyaWZpY2FyIHRpcG8gZG8gdG9rZW5cbiAgICAgIGlmIChwYXlsb2FkLnR5cCAhPT0gJ2FjY2VzcycpIHtcbiAgICAgICAgcmV0dXJuIHsgdmFsaWQ6IGZhbHNlLCBlcnJvcjogJ1RpcG8gZGUgdG9rZW4gaW5jb3JyZXRvJyB9O1xuICAgICAgfVxuXG4gICAgICAvLyBWZXJpZmljYXIgc2Ugc2Vzc8OjbyBleGlzdGUgZSBuw6NvIGZvaSByZXZvZ2FkYVxuICAgICAgY29uc3QgZGIgPSBnZXREQigpO1xuICAgICAgY29uc3Qgc2Vzc2lvbnMgPSBhd2FpdCBkYlxuICAgICAgICAuc2VsZWN0KHsgcmV2b2tlZDogc2NoZW1hLnNlc3Npb25zLnJldm9rZWQgfSlcbiAgICAgICAgLmZyb20oc2NoZW1hLnNlc3Npb25zKVxuICAgICAgICAud2hlcmUoZXEoc2NoZW1hLnNlc3Npb25zLmlkLCBwYXlsb2FkLnNpZCkpXG4gICAgICAgIC5saW1pdCgxKTtcblxuICAgICAgaWYgKCFzZXNzaW9ucyB8fCBzZXNzaW9ucy5sZW5ndGggPT09IDApIHtcbiAgICAgICAgcmV0dXJuIHsgdmFsaWQ6IGZhbHNlLCBlcnJvcjogJ1Nlc3PDo28gbsOjbyBlbmNvbnRyYWRhJyB9O1xuICAgICAgfVxuXG4gICAgICBpZiAoc2Vzc2lvbnNbMF0ucmV2b2tlZCkge1xuICAgICAgICByZXR1cm4geyB2YWxpZDogZmFsc2UsIGVycm9yOiAnU2Vzc8OjbyByZXZvZ2FkYScgfTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHsgdmFsaWQ6IHRydWUsIHBheWxvYWQgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgY29uc29sZS5lcnJvcignRXJybyBhbyB2YWxpZGFyIGFjY2VzcyB0b2tlbjonLCBlcnJvcik7XG4gICAgICByZXR1cm4geyB2YWxpZDogZmFsc2UsIGVycm9yOiAnRXJybyBhbyB2YWxpZGFyIHRva2VuJyB9O1xuICAgIH1cbiAgfSxcblxuICAvKipcbiAgICogUmVhbGl6YSByZWZyZXNoIGRvIGFjY2VzcyB0b2tlbiB1c2FuZG8gcmVmcmVzaCB0b2tlblxuICAgKiBJbXBsZW1lbnRhIHJvdGHDp8OjbyBkZSByZWZyZXNoIHRva2VucyBwYXJhIHNlZ3VyYW7Dp2FcbiAgICovXG4gIGFzeW5jIHJlZnJlc2hBY2Nlc3NUb2tlbihyZWZyZXNoVG9rZW46IHN0cmluZywgaXBBZGRyZXNzOiBzdHJpbmcsIHVzZXJBZ2VudDogc3RyaW5nKTogUHJvbWlzZTx7IHN1Y2Nlc3M6IGJvb2xlYW47IHNlc3Npb24/OiBTZXNzaW9uRGF0YTsgZXJyb3I/OiBhbnkgfT4ge1xuICAgIGNvbnN0IGRiID0gZ2V0REIoKTtcblxuICAgIHRyeSB7XG4gICAgICAvLyBWZXJpZmljYXIgcmVmcmVzaCB0b2tlblxuICAgICAgY29uc3Qgand0UmVzdWx0ID0gYXdhaXQgdmVyaWZ5SldUKHJlZnJlc2hUb2tlbik7XG4gICAgICBcbiAgICAgIGlmICghand0UmVzdWx0LnZhbGlkIHx8ICFqd3RSZXN1bHQucGF5bG9hZCkge1xuICAgICAgICByZXR1cm4geyBzdWNjZXNzOiBmYWxzZSwgZXJyb3I6IHsgY29kZTogJ0lOVkFMSURfVE9LRU4nLCBtZXNzYWdlOiAnUmVmcmVzaCB0b2tlbiBpbnbDoWxpZG8gb3UgZXhwaXJhZG8nIH0gfTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgcGF5bG9hZCA9IGp3dFJlc3VsdC5wYXlsb2FkIGFzIFJlZnJlc2hUb2tlblBheWxvYWQ7XG5cbiAgICAgIC8vIFZlcmlmaWNhciB0aXBvXG4gICAgICBpZiAocGF5bG9hZC50eXAgIT09ICdyZWZyZXNoJykge1xuICAgICAgICByZXR1cm4geyBzdWNjZXNzOiBmYWxzZSwgZXJyb3I6IHsgY29kZTogJ0lOVkFMSURfVE9LRU5fVFlQRScsIG1lc3NhZ2U6ICdUaXBvIGRlIHRva2VuIGluY29ycmV0bycgfSB9O1xuICAgICAgfVxuXG4gICAgICAvLyBCdXNjYXIgc2Vzc8Ojb1xuICAgICAgY29uc3Qgc2Vzc2lvbnMgPSBhd2FpdCBkYlxuICAgICAgICAuc2VsZWN0KClcbiAgICAgICAgLmZyb20oc2NoZW1hLnNlc3Npb25zKVxuICAgICAgICAud2hlcmUoXG4gICAgICAgICAgYW5kKFxuICAgICAgICAgICAgZXEoc2NoZW1hLnNlc3Npb25zLmlkLCBwYXlsb2FkLnNpZCksXG4gICAgICAgICAgICBlcShzY2hlbWEuc2Vzc2lvbnMucmV2b2tlZCwgZmFsc2UpXG4gICAgICAgICAgKVxuICAgICAgICApXG4gICAgICAgIC5saW1pdCgxKTtcblxuICAgICAgaWYgKCFzZXNzaW9ucyB8fCBzZXNzaW9ucy5sZW5ndGggPT09IDApIHtcbiAgICAgICAgcmV0dXJuIHsgc3VjY2VzczogZmFsc2UsIGVycm9yOiB7IGNvZGU6ICdTRVNTSU9OX05PVF9GT1VORCcsIG1lc3NhZ2U6ICdTZXNzw6NvIG7Do28gZW5jb250cmFkYSBvdSByZXZvZ2FkYScgfSB9O1xuICAgICAgfVxuXG4gICAgICBjb25zdCBzZXNzaW9uID0gc2Vzc2lvbnNbMF07XG5cbiAgICAgIC8vIFZlcmlmaWNhciBleHBpcnlcbiAgICAgIGlmIChuZXcgRGF0ZShzZXNzaW9uLnJlZnJlc2hFeHBpcmVzQXQpIDwgbmV3IERhdGUoKSkge1xuICAgICAgICAvLyBTZXNzw6NvIGV4cGlyYWRhLCByZXZvZ2FyXG4gICAgICAgIGF3YWl0IGRiXG4gICAgICAgICAgLnVwZGF0ZShzY2hlbWEuc2Vzc2lvbnMpXG4gICAgICAgICAgLnNldCh7IHJldm9rZWQ6IHRydWUgfSlcbiAgICAgICAgICAud2hlcmUoZXEoc2NoZW1hLnNlc3Npb25zLmlkLCBzZXNzaW9uLmlkKSk7XG5cbiAgICAgICAgcmV0dXJuIHsgc3VjY2VzczogZmFsc2UsIGVycm9yOiB7IGNvZGU6ICdTRVNTSU9OX0VYUElSRUQnLCBtZXNzYWdlOiAnU2Vzc8OjbyBleHBpcmFkYScgfSB9O1xuICAgICAgfVxuXG4gICAgICAvLyBWZXJpZmljYXIgaGFzaCBkbyByZWZyZXNoIHRva2VuIChkZXRlY8Onw6NvIGRlIHJvdWJvL3JlcGxheSlcbiAgICAgIGNvbnN0IGluY29taW5nSGFzaCA9IGF3YWl0IHNoYTI1NihyZWZyZXNoVG9rZW4pO1xuICAgICAgXG4gICAgICAvLyBTZSBvIGhhc2ggbsOjbyBiYXRlciwgcG9kZSBpbmRpY2FyIHRva2VuIHJvdWJhZG8gc2VuZG8gdXNhZG8gcG9yIGF0YWNhbnRlXG4gICAgICAvLyBFbSBwcm9kdcOnw6NvOiBpbnZhbGlkYXIgVE9EQVMgYXMgc2Vzc8O1ZXMgZG8gdXN1w6FyaW9cbiAgICAgIGlmIChzZXNzaW9uLnJlZnJlc2hUb2tlbkhhc2ggIT09IGluY29taW5nSGFzaCkge1xuICAgICAgICBjb25zb2xlLndhcm4oJ1Bvc3PDrXZlbCBhdGFxdWUgZGUgcmVwbGF5IGRldGVjdGFkbyAtIHJlZnJlc2ggdG9rZW4gbWlzbWF0Y2gnKTtcbiAgICAgICAgXG4gICAgICAgIC8vIFJldm9nYXIgdG9kYXMgYXMgc2Vzc8O1ZXMgZG8gdXN1w6FyaW8gY29tbyBtZWRpZGEgZGUgc2VndXJhbsOnYVxuICAgICAgICBhd2FpdCBkYlxuICAgICAgICAgIC51cGRhdGUoc2NoZW1hLnNlc3Npb25zKVxuICAgICAgICAgIC5zZXQoeyByZXZva2VkOiB0cnVlIH0pXG4gICAgICAgICAgLndoZXJlKGVxKHNjaGVtYS5zZXNzaW9ucy51c2VySWQsIHBheWxvYWQuc3ViKSk7XG5cbiAgICAgICAgLy8gQXVkaXRvcmlhIGRlIHNlZ3VyYW7Dp2FcbiAgICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgICAgYWN0aW9uOiAnVE9LRU5fUkVGUkVTSF9GQUlMVVJFJyxcbiAgICAgICAgICB1c2VySWQ6IHBheWxvYWQuc3ViLFxuICAgICAgICAgIHNlc3Npb25JZDogcGF5bG9hZC5zaWQsXG4gICAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLFxuICAgICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgICB1c2VyQWdlbnQsXG4gICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgZmFpbHVyZVJlYXNvbjogJ1Bvc3NpYmxlIHJlcGxheSBhdHRhY2sgZGV0ZWN0ZWQgLSByZWZyZXNoIHRva2VuIG1pc21hdGNoJyxcbiAgICAgICAgfSk7XG5cbiAgICAgICAgcmV0dXJuIHsgXG4gICAgICAgICAgc3VjY2VzczogZmFsc2UsIFxuICAgICAgICAgIGVycm9yOiB7IGNvZGU6ICdTRUNVUklUWV9WSU9MQVRJT04nLCBtZXNzYWdlOiAnVmlvbGHDp8OjbyBkZSBzZWd1cmFuw6dhIGRldGVjdGFkYS4gVG9kYXMgYXMgc2Vzc8O1ZXMgZm9yYW0gcmV2b2dhZGFzLicgfSBcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgLy8gR2VyYXIgbm92b3MgdG9rZW5zIChyb3Rhw6fDo28pXG4gICAgICBjb25zdCBuZXdUb2tlbnMgPSBhd2FpdCBnZW5lcmF0ZUF1dGhUb2tlbnMoe1xuICAgICAgICB1c2VySWQ6IHBheWxvYWQuc3ViLFxuICAgICAgICBzZXNzaW9uSWQ6IHBheWxvYWQuc2lkLFxuICAgICAgICBtZmFWZXJpZmllZDogdHJ1ZSwgLy8gQXNzdW1pbmRvIHF1ZSBqw6EgZm9pIHZlcmlmaWNhZG8gbm8gbG9naW5cbiAgICAgICAgY291bnRlcjogcGF5bG9hZC5jb3VudGVyICsgMSxcbiAgICAgIH0pO1xuXG4gICAgICAvLyBBdHVhbGl6YXIgc2Vzc8OjbyBjb20gbm92byByZWZyZXNoIHRva2VuIGhhc2hcbiAgICAgIGF3YWl0IGRiXG4gICAgICAgIC51cGRhdGUoc2NoZW1hLnNlc3Npb25zKVxuICAgICAgICAuc2V0KHtcbiAgICAgICAgICByZWZyZXNoVG9rZW5IYXNoOiBhd2FpdCBzaGEyNTYobmV3VG9rZW5zLnJlZnJlc2hUb2tlbiksXG4gICAgICAgICAgZXhwaXJlc0F0OiBuZXdUb2tlbnMuZXhwaXJlc0F0LFxuICAgICAgICAgIHJlZnJlc2hFeHBpcmVzQXQ6IG5ld1Rva2Vucy5yZWZyZXNoRXhwaXJlc0F0LFxuICAgICAgICB9KVxuICAgICAgICAud2hlcmUoZXEoc2NoZW1hLnNlc3Npb25zLmlkLCBzZXNzaW9uLmlkKSk7XG5cbiAgICAgIC8vIEJ1c2NhciBkYWRvcyBkbyBkaXNwb3NpdGl2b1xuICAgICAgY29uc3QgZGV2aWNlcyA9IGF3YWl0IGRiXG4gICAgICAgIC5zZWxlY3QoKVxuICAgICAgICAuZnJvbShzY2hlbWEuZGV2aWNlcylcbiAgICAgICAgLndoZXJlKGVxKHNjaGVtYS5kZXZpY2VzLnVzZXJJZCwgcGF5bG9hZC5zdWIpKVxuICAgICAgICAubGltaXQoMSk7XG5cbiAgICAgIGNvbnN0IGRldmljZSA9IGRldmljZXMgJiYgZGV2aWNlcy5sZW5ndGggPiAwID8gZGV2aWNlc1swXSA6IHVuZGVmaW5lZDtcblxuICAgICAgY29uc3Qgc2Vzc2lvbkRhdGE6IFNlc3Npb25EYXRhID0ge1xuICAgICAgICBzZXNzaW9uSWQ6IHBheWxvYWQuc2lkLFxuICAgICAgICB1c2VySWQ6IHBheWxvYWQuc3ViLFxuICAgICAgICBhY2Nlc3NUb2tlbjogbmV3VG9rZW5zLmFjY2Vzc1Rva2VuLFxuICAgICAgICByZWZyZXNoVG9rZW46IG5ld1Rva2Vucy5yZWZyZXNoVG9rZW4sXG4gICAgICAgIGV4cGlyZXNBdDogbmV3VG9rZW5zLmV4cGlyZXNBdCxcbiAgICAgICAgcmVmcmVzaEV4cGlyZXNBdDogbmV3VG9rZW5zLnJlZnJlc2hFeHBpcmVzQXQsXG4gICAgICAgIGRldmljZTogZGV2aWNlID8ge1xuICAgICAgICAgIGRldmljZUlkOiBkZXZpY2UuaWQsXG4gICAgICAgICAgbmFtZTogZGV2aWNlLm5hbWUsXG4gICAgICAgICAgdHlwZTogZGV2aWNlLnR5cGUgYXMgYW55LFxuICAgICAgICAgIG9zOiBkZXZpY2Uub3MgfHwgJycsXG4gICAgICAgICAgYnJvd3NlcjogZGV2aWNlLmJyb3dzZXIgfHwgJycsXG4gICAgICAgICAgaXNUcnVzdGVkOiBkZXZpY2UuaXNUcnVzdGVkLFxuICAgICAgICAgIGxhc3RTZWVuQXQ6IGRldmljZS5sYXN0U2VlbkF0LFxuICAgICAgICAgIGlwQWRkcmVzczogZGV2aWNlLmlwQWRkcmVzcyB8fCB1bmRlZmluZWQsXG4gICAgICAgICAgdXNlckFnZW50OiBkZXZpY2UudXNlckFnZW50IHx8IHVuZGVmaW5lZCxcbiAgICAgICAgfSA6IHVuZGVmaW5lZCxcbiAgICAgICAgbWZhVmVyaWZpZWQ6IHRydWUsXG4gICAgICAgIGNyZWF0ZWRBdDogc2Vzc2lvbi5jcmVhdGVkQXQsXG4gICAgICB9O1xuXG4gICAgICAvLyBBdWRpdG9yaWFcbiAgICAgIGF3YWl0IHRoaXMuYXVkaXRMb2coe1xuICAgICAgICBhY3Rpb246ICdUT0tFTl9SRUZSRVNIX1NVQ0NFU1MnLFxuICAgICAgICB1c2VySWQ6IHBheWxvYWQuc3ViLFxuICAgICAgICBzZXNzaW9uSWQ6IHBheWxvYWQuc2lkLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IHRydWUsIHNlc3Npb246IHNlc3Npb25EYXRhIH07XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm8gYW8gcmVmcmVzaCBhY2Nlc3MgdG9rZW46JywgZXJyb3IpO1xuICAgICAgcmV0dXJuIHsgc3VjY2VzczogZmFsc2UsIGVycm9yOiB7IGNvZGU6ICdJTlRFUk5BTF9FUlJPUicsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLklOVEVSTkFMX0VSUk9SIH0gfTtcbiAgICB9XG4gIH0sXG5cbiAgLyoqXG4gICAqIFJldm9nYSB1bWEgc2Vzc8OjbyBlc3BlY8OtZmljYVxuICAgKi9cbiAgYXN5bmMgcmV2b2tlU2Vzc2lvbihzZXNzaW9uSWQ6IHN0cmluZywgdXNlcklkOiBzdHJpbmcsIGlwQWRkcmVzczogc3RyaW5nLCB1c2VyQWdlbnQ6IHN0cmluZyk6IFByb21pc2U8eyBzdWNjZXNzOiBib29sZWFuOyBlcnJvcj86IGFueSB9PiB7XG4gICAgY29uc3QgZGIgPSBnZXREQigpO1xuXG4gICAgdHJ5IHtcbiAgICAgIC8vIFZlcmlmaWNhciBvd25lcnNoaXAgZGEgc2Vzc8Ojb1xuICAgICAgY29uc3Qgc2Vzc2lvbnMgPSBhd2FpdCBkYlxuICAgICAgICAuc2VsZWN0KClcbiAgICAgICAgLmZyb20oc2NoZW1hLnNlc3Npb25zKVxuICAgICAgICAud2hlcmUoXG4gICAgICAgICAgYW5kKFxuICAgICAgICAgICAgZXEoc2NoZW1hLnNlc3Npb25zLmlkLCBzZXNzaW9uSWQpLFxuICAgICAgICAgICAgZXEoc2NoZW1hLnNlc3Npb25zLnVzZXJJZCwgdXNlcklkKVxuICAgICAgICAgIClcbiAgICAgICAgKVxuICAgICAgICAubGltaXQoMSk7XG5cbiAgICAgIGlmICghc2Vzc2lvbnMgfHwgc2Vzc2lvbnMubGVuZ3RoID09PSAwKSB7XG4gICAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IGZhbHNlLCBlcnJvcjogeyBjb2RlOiAnU0VTU0lPTl9OT1RfRk9VTkQnLCBtZXNzYWdlOiAnU2Vzc8OjbyBuw6NvIGVuY29udHJhZGEnIH0gfTtcbiAgICAgIH1cblxuICAgICAgLy8gUmV2b2dhciBzZXNzw6NvXG4gICAgICBhd2FpdCBkYlxuICAgICAgICAudXBkYXRlKHNjaGVtYS5zZXNzaW9ucylcbiAgICAgICAgLnNldCh7IHJldm9rZWQ6IHRydWUgfSlcbiAgICAgICAgLndoZXJlKGVxKHNjaGVtYS5zZXNzaW9ucy5pZCwgc2Vzc2lvbklkKSk7XG5cbiAgICAgIC8vIEF1ZGl0b3JpYVxuICAgICAgYXdhaXQgdGhpcy5hdWRpdExvZyh7XG4gICAgICAgIGFjdGlvbjogJ1NFU1NJT05fUkVWT0tFRCcsXG4gICAgICAgIHVzZXJJZCxcbiAgICAgICAgc2Vzc2lvbklkLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50LFxuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IHRydWUgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgY29uc29sZS5lcnJvcignRXJybyBhbyByZXZvZ2FyIHNlc3PDo286JywgZXJyb3IpO1xuICAgICAgcmV0dXJuIHsgc3VjY2VzczogZmFsc2UsIGVycm9yOiB7IGNvZGU6ICdJTlRFUk5BTF9FUlJPUicsIG1lc3NhZ2U6IEFVVEhfQ09OU1RBTlRTLkVSUk9SX01FU1NBR0VTLklOVEVSTkFMX0VSUk9SIH0gfTtcbiAgICB9XG4gIH0sXG5cbiAgLyoqXG4gICAqIFJldm9nYSBUT0RBUyBhcyBzZXNzw7VlcyBkZSB1bSB1c3XDoXJpbyAobG9nb3V0IGVtIHRvZG9zIG9zIGRpc3Bvc2l0aXZvcylcbiAgICovXG4gIGFzeW5jIHJldm9rZUFsbFNlc3Npb25zKHVzZXJJZDogc3RyaW5nLCBleGNlcHRTZXNzaW9uSWQ/OiBzdHJpbmcsIGlwQWRkcmVzcz86IHN0cmluZywgdXNlckFnZW50Pzogc3RyaW5nKTogUHJvbWlzZTx7IHN1Y2Nlc3M6IGJvb2xlYW47IGVycm9yPzogYW55IH0+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG5cbiAgICB0cnkge1xuICAgICAgY29uc3QgdXBkYXRlUXVlcnkgPSBkYlxuICAgICAgICAudXBkYXRlKHNjaGVtYS5zZXNzaW9ucylcbiAgICAgICAgLnNldCh7IHJldm9rZWQ6IHRydWUgfSlcbiAgICAgICAgLndoZXJlKFxuICAgICAgICAgIGFuZChcbiAgICAgICAgICAgIGVxKHNjaGVtYS5zZXNzaW9ucy51c2VySWQsIHVzZXJJZCksXG4gICAgICAgICAgICBleGNlcHRTZXNzaW9uSWQgPyBlcShzY2hlbWEuc2Vzc2lvbnMucmV2b2tlZCwgZmFsc2UpIDogdW5kZWZpbmVkXG4gICAgICAgICAgKVxuICAgICAgICApO1xuXG4gICAgICAvLyBTZSBleGNldG8gdW1hIHNlc3PDo28sIGFkaWNpb25hciBjb25kacOnw6NvXG4gICAgICBpZiAoZXhjZXB0U2Vzc2lvbklkKSB7XG4gICAgICAgIGF3YWl0IGRiXG4gICAgICAgICAgLnVwZGF0ZShzY2hlbWEuc2Vzc2lvbnMpXG4gICAgICAgICAgLnNldCh7IHJldm9rZWQ6IHRydWUgfSlcbiAgICAgICAgICAud2hlcmUoXG4gICAgICAgICAgICBhbmQoXG4gICAgICAgICAgICAgIGVxKHNjaGVtYS5zZXNzaW9ucy51c2VySWQsIHVzZXJJZCksXG4gICAgICAgICAgICAgIHNxbGAke3NjaGVtYS5zZXNzaW9ucy5pZH0gIT0gJHtleGNlcHRTZXNzaW9uSWR9YFxuICAgICAgICAgICAgKVxuICAgICAgICAgICk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBhd2FpdCB1cGRhdGVRdWVyeTtcbiAgICAgIH1cblxuICAgICAgLy8gQXVkaXRvcmlhXG4gICAgICBhd2FpdCB0aGlzLmF1ZGl0TG9nKHtcbiAgICAgICAgYWN0aW9uOiAnU0VTU0lPTl9SRVZPS0VEJyxcbiAgICAgICAgdXNlcklkLFxuICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCksXG4gICAgICAgIGlwQWRkcmVzczogaXBBZGRyZXNzIHx8ICcnLFxuICAgICAgICB1c2VyQWdlbnQ6IHVzZXJBZ2VudCB8fCAnJyxcbiAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgbWV0YWRhdGE6IHsgYWxsU2Vzc2lvbnM6IHRydWUsIGV4Y2VwdFNlc3Npb25JZCB9LFxuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IHRydWUgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgY29uc29sZS5lcnJvcignRXJybyBhbyByZXZvZ2FyIHRvZGFzIGFzIHNlc3PDtWVzOicsIGVycm9yKTtcbiAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IGZhbHNlLCBlcnJvcjogeyBjb2RlOiAnSU5URVJOQUxfRVJST1InLCBtZXNzYWdlOiBBVVRIX0NPTlNUQU5UUy5FUlJPUl9NRVNTQUdFUy5JTlRFUk5BTF9FUlJPUiB9IH07XG4gICAgfVxuICB9LFxuXG4gIC8qKlxuICAgKiBMb2dvdXQgLSByZXZvZ2Egc2Vzc8OjbyBhdHVhbFxuICAgKi9cbiAgYXN5bmMgbG9nb3V0KHNlc3Npb25JZDogc3RyaW5nLCB1c2VySWQ6IHN0cmluZywgaXBBZGRyZXNzOiBzdHJpbmcsIHVzZXJBZ2VudDogc3RyaW5nKTogUHJvbWlzZTx7IHN1Y2Nlc3M6IGJvb2xlYW47IGVycm9yPzogYW55IH0+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy5yZXZva2VTZXNzaW9uKHNlc3Npb25JZCwgdXNlcklkLCBpcEFkZHJlc3MsIHVzZXJBZ2VudCk7XG4gIH0sXG5cbiAgLyoqXG4gICAqIExpc3RhIHNlc3PDtWVzIGF0aXZhcyBkZSB1bSB1c3XDoXJpb1xuICAgKi9cbiAgYXN5bmMgbGlzdEFjdGl2ZVNlc3Npb25zKHVzZXJJZDogc3RyaW5nKTogUHJvbWlzZTx7IHN1Y2Nlc3M6IGJvb2xlYW47IHNlc3Npb25zPzogYW55W107IGVycm9yPzogYW55IH0+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG5cbiAgICB0cnkge1xuICAgICAgY29uc3Qgc2Vzc2lvbnMgPSBhd2FpdCBkYlxuICAgICAgICAuc2VsZWN0KHtcbiAgICAgICAgICBzZXNzaW9uSWQ6IHNjaGVtYS5zZXNzaW9ucy5pZCxcbiAgICAgICAgICBjcmVhdGVkQXQ6IHNjaGVtYS5zZXNzaW9ucy5jcmVhdGVkQXQsXG4gICAgICAgICAgZXhwaXJlc0F0OiBzY2hlbWEuc2Vzc2lvbnMuZXhwaXJlc0F0LFxuICAgICAgICAgIHJlZnJlc2hFeHBpcmVzQXQ6IHNjaGVtYS5zZXNzaW9ucy5yZWZyZXNoRXhwaXJlc0F0LFxuICAgICAgICAgIGRldmljZU5hbWU6IHNjaGVtYS5kZXZpY2VzLm5hbWUsXG4gICAgICAgICAgZGV2aWNlVHlwZTogc2NoZW1hLmRldmljZXMudHlwZSxcbiAgICAgICAgICBkZXZpY2VPUzogc2NoZW1hLmRldmljZXMub3MsXG4gICAgICAgICAgZGV2aWNlQnJvd3Nlcjogc2NoZW1hLmRldmljZXMuYnJvd3NlcixcbiAgICAgICAgICBkZXZpY2VJc1RydXN0ZWQ6IHNjaGVtYS5kZXZpY2VzLmlzVHJ1c3RlZCxcbiAgICAgICAgICBkZXZpY2VMYXN0U2VlbkF0OiBzY2hlbWEuZGV2aWNlcy5sYXN0U2VlbkF0LFxuICAgICAgICAgIGRldmljZUlwQWRkcmVzczogc2NoZW1hLmRldmljZXMuaXBBZGRyZXNzLFxuICAgICAgICB9KVxuICAgICAgICAuZnJvbShzY2hlbWEuc2Vzc2lvbnMpXG4gICAgICAgIC5sZWZ0Sm9pbihzY2hlbWEuZGV2aWNlcywgZXEoc2NoZW1hLnNlc3Npb25zLmlkLCBzY2hlbWEuZGV2aWNlcy51c2VySWQpKVxuICAgICAgICAud2hlcmUoXG4gICAgICAgICAgYW5kKFxuICAgICAgICAgICAgZXEoc2NoZW1hLnNlc3Npb25zLnVzZXJJZCwgdXNlcklkKSxcbiAgICAgICAgICAgIGVxKHNjaGVtYS5zZXNzaW9ucy5yZXZva2VkLCBmYWxzZSlcbiAgICAgICAgICApXG4gICAgICAgICk7XG5cbiAgICAgIHJldHVybiB7IFxuICAgICAgICBzdWNjZXNzOiB0cnVlLCBcbiAgICAgICAgc2Vzc2lvbnM6IHNlc3Npb25zLm1hcCgoczogYW55KSA9PiAoe1xuICAgICAgICAgIHNlc3Npb25JZDogcy5zZXNzaW9uSWQsXG4gICAgICAgICAgY3JlYXRlZEF0OiBzLmNyZWF0ZWRBdCxcbiAgICAgICAgICBleHBpcmVzQXQ6IHMuZXhwaXJlc0F0LFxuICAgICAgICAgIGRldmljZToge1xuICAgICAgICAgICAgbmFtZTogcy5kZXZpY2VOYW1lLFxuICAgICAgICAgICAgdHlwZTogcy5kZXZpY2VUeXBlLFxuICAgICAgICAgICAgb3M6IHMuZGV2aWNlT1MsXG4gICAgICAgICAgICBicm93c2VyOiBzLmRldmljZUJyb3dzZXIsXG4gICAgICAgICAgICBpc1RydXN0ZWQ6IHMuZGV2aWNlSXNUcnVzdGVkLFxuICAgICAgICAgICAgbGFzdFNlZW5BdDogcy5kZXZpY2VMYXN0U2VlbkF0LFxuICAgICAgICAgICAgaXBBZGRyZXNzOiBzLmRldmljZUlwQWRkcmVzcyxcbiAgICAgICAgICB9LFxuICAgICAgICB9KSlcbiAgICAgIH07XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm8gYW8gbGlzdGFyIHNlc3PDtWVzOicsIGVycm9yKTtcbiAgICAgIHJldHVybiB7IHN1Y2Nlc3M6IGZhbHNlLCBlcnJvcjogeyBjb2RlOiAnSU5URVJOQUxfRVJST1InLCBtZXNzYWdlOiBBVVRIX0NPTlNUQU5UUy5FUlJPUl9NRVNTQUdFUy5JTlRFUk5BTF9FUlJPUiB9IH07XG4gICAgfVxuICB9LFxuXG4gIC8qKlxuICAgKiBWZXJpZmljYSBzZSBkaXNwb3NpdGl2byDDqSBjb25macOhdmVsXG4gICAqL1xuICBhc3luYyBpc1RydXN0ZWREZXZpY2UodXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBjb25zdCBkYiA9IGdldERCKCk7XG5cbiAgICB0cnkge1xuICAgICAgY29uc3QgZGV2aWNlcyA9IGF3YWl0IGRiXG4gICAgICAgIC5zZWxlY3QoeyBpc1RydXN0ZWQ6IHNjaGVtYS5kZXZpY2VzLmlzVHJ1c3RlZCwgdHJ1c3RlZFVudGlsOiBzY2hlbWEuZGV2aWNlcy50cnVzdGVkVW50aWwgfSlcbiAgICAgICAgLmZyb20oc2NoZW1hLmRldmljZXMpXG4gICAgICAgIC53aGVyZShcbiAgICAgICAgICBhbmQoXG4gICAgICAgICAgICBlcShzY2hlbWEuZGV2aWNlcy5pZCwgZGV2aWNlSWQpLFxuICAgICAgICAgICAgZXEoc2NoZW1hLmRldmljZXMudXNlcklkLCB1c2VySWQpXG4gICAgICAgICAgKVxuICAgICAgICApXG4gICAgICAgIC5saW1pdCgxKTtcblxuICAgICAgaWYgKCFkZXZpY2VzIHx8IGRldmljZXMubGVuZ3RoID09PSAwKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgZGV2aWNlID0gZGV2aWNlc1swXTtcblxuICAgICAgaWYgKCFkZXZpY2UuaXNUcnVzdGVkKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cblxuICAgICAgLy8gVmVyaWZpY2FyIHNlIHRydXN0IGFpbmRhIHbDoWxpZG9cbiAgICAgIGlmIChkZXZpY2UudHJ1c3RlZFVudGlsICYmIG5ldyBEYXRlKGRldmljZS50cnVzdGVkVW50aWwpIDwgbmV3IERhdGUoKSkge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdFcnJvIGFvIHZlcmlmaWNhciBkaXNwb3NpdGl2byBjb25macOhdmVsOicsIGVycm9yKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gIH0sXG5cbiAgYXN5bmMgYXVkaXRMb2coZXZlbnQ6IEF1dGhBdWRpdEV2ZW50KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGIgPSBnZXREQigpO1xuICAgIFxuICAgIHRyeSB7XG4gICAgICBhd2FpdCBkYi5pbnNlcnQoc2NoZW1hLmF1ZGl0TG9ncykudmFsdWVzKHtcbiAgICAgICAgaWQ6IGdlbmVyYXRlVVVJRCgpLFxuICAgICAgICBhY3Rpb246IGV2ZW50LmFjdGlvbixcbiAgICAgICAgdXNlcklkOiBldmVudC51c2VySWQgfHwgbnVsbCxcbiAgICAgICAgc2Vzc2lvbklkOiBldmVudC5zZXNzaW9uSWQgfHwgbnVsbCxcbiAgICAgICAgZGV2aWNlSWQ6IGV2ZW50LmRldmljZUlkIHx8IG51bGwsXG4gICAgICAgIHRpbWVzdGFtcDogZXZlbnQudGltZXN0YW1wLFxuICAgICAgICBpcEFkZHJlc3M6IGV2ZW50LmlwQWRkcmVzcyxcbiAgICAgICAgdXNlckFnZW50OiBldmVudC51c2VyQWdlbnQsXG4gICAgICAgIHN1Y2Nlc3M6IGV2ZW50LnN1Y2Nlc3MsXG4gICAgICAgIGZhaWx1cmVSZWFzb246IGV2ZW50LmZhaWx1cmVSZWFzb24gfHwgbnVsbCxcbiAgICAgICAgbWV0YWRhdGE6IGV2ZW50Lm1ldGFkYXRhID8gSlNPTi5zdHJpbmdpZnkoZXZlbnQubWV0YWRhdGEpIDogbnVsbCxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdFcnJvIGFvIGNyaWFyIGxvZyBkZSBhdWRpdG9yaWE6JywgZXJyb3IpO1xuICAgIH1cbiAgfSxcbn07XG5cbi8vIEhlbHBlciBwYXJhIFNRTCAoaW1wb3J0YXIgZGUgZHJpenpsZS1vcm0pXG5jb25zdCBzcWwgPSB7XG4gIG5vdDogKHZhbHVlOiBhbnkpID0+IHZhbHVlLFxuICBuZTogKGNvbDogYW55LCB2YWw6IGFueSkgPT4gKHsgY29sLCB2YWwsIG9wOiAnIT0nIH0pLFxufTtcbiJdfQ==
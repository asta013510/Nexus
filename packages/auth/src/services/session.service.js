"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionService = void 0;
exports.setDatabaseClient = setDatabaseClient;
const drizzle_orm_1 = require("drizzle-orm");
const crypto_1 = require("@zero/crypto");
const database_1 = require("@zero/database");
const shared_1 = require("@zero/shared");
const constants_1 = require("../constants");
const tokens_1 = require("../utils/tokens");
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
exports.SessionService = {
    /**
     * Valida access token JWT
     */
    async validateAccessToken(accessToken) {
        try {
            const result = await (0, crypto_1.verifyJWT)(accessToken);
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
                .select({ revoked: database_1.schema.sessions.revoked })
                .from(database_1.schema.sessions)
                .where((0, drizzle_orm_1.eq)(database_1.schema.sessions.id, payload.sid))
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
            const jwtResult = await (0, crypto_1.verifyJWT)(refreshToken);
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
                .from(database_1.schema.sessions)
                .where((0, drizzle_orm_1.and)((0, drizzle_orm_1.eq)(database_1.schema.sessions.id, payload.sid), (0, drizzle_orm_1.eq)(database_1.schema.sessions.revoked, false)))
                .limit(1);
            if (!sessions || sessions.length === 0) {
                return { success: false, error: { code: 'SESSION_NOT_FOUND', message: 'Sessão não encontrada ou revogada' } };
            }
            const session = sessions[0];
            // Verificar expiry
            if (new Date(session.refreshExpiresAt) < new Date()) {
                // Sessão expirada, revogar
                await db
                    .update(database_1.schema.sessions)
                    .set({ revoked: true })
                    .where((0, drizzle_orm_1.eq)(database_1.schema.sessions.id, session.id));
                return { success: false, error: { code: 'SESSION_EXPIRED', message: 'Sessão expirada' } };
            }
            // Verificar hash do refresh token (detecção de roubo/replay)
            const incomingHash = await (0, crypto_1.sha256)(refreshToken);
            // Se o hash não bater, pode indicar token roubado sendo usado por atacante
            // Em produção: invalidar TODAS as sessões do usuário
            if (session.refreshTokenHash !== incomingHash) {
                console.warn('Possível ataque de replay detectado - refresh token mismatch');
                // Revogar todas as sessões do usuário como medida de segurança
                await db
                    .update(database_1.schema.sessions)
                    .set({ revoked: true })
                    .where((0, drizzle_orm_1.eq)(database_1.schema.sessions.userId, payload.sub));
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
            const newTokens = await (0, tokens_1.generateAuthTokens)({
                userId: payload.sub,
                sessionId: payload.sid,
                mfaVerified: true, // Assumindo que já foi verificado no login
                counter: payload.counter + 1,
            });
            // Atualizar sessão com novo refresh token hash
            await db
                .update(database_1.schema.sessions)
                .set({
                refreshTokenHash: await (0, crypto_1.sha256)(newTokens.refreshToken),
                expiresAt: newTokens.expiresAt,
                refreshExpiresAt: newTokens.refreshExpiresAt,
            })
                .where((0, drizzle_orm_1.eq)(database_1.schema.sessions.id, session.id));
            // Buscar dados do dispositivo
            const devices = await db
                .select()
                .from(database_1.schema.devices)
                .where((0, drizzle_orm_1.eq)(database_1.schema.devices.userId, payload.sub))
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
            return { success: false, error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR } };
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
                .from(database_1.schema.sessions)
                .where((0, drizzle_orm_1.and)((0, drizzle_orm_1.eq)(database_1.schema.sessions.id, sessionId), (0, drizzle_orm_1.eq)(database_1.schema.sessions.userId, userId)))
                .limit(1);
            if (!sessions || sessions.length === 0) {
                return { success: false, error: { code: 'SESSION_NOT_FOUND', message: 'Sessão não encontrada' } };
            }
            // Revogar sessão
            await db
                .update(database_1.schema.sessions)
                .set({ revoked: true })
                .where((0, drizzle_orm_1.eq)(database_1.schema.sessions.id, sessionId));
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
            return { success: false, error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR } };
        }
    },
    /**
     * Revoga TODAS as sessões de um usuário (logout em todos os dispositivos)
     */
    async revokeAllSessions(userId, exceptSessionId, ipAddress, userAgent) {
        const db = getDB();
        try {
            const updateQuery = db
                .update(database_1.schema.sessions)
                .set({ revoked: true })
                .where((0, drizzle_orm_1.and)((0, drizzle_orm_1.eq)(database_1.schema.sessions.userId, userId), exceptSessionId ? (0, drizzle_orm_1.eq)(database_1.schema.sessions.revoked, false) : undefined));
            // Se exceto uma sessão, adicionar condição
            if (exceptSessionId) {
                await db
                    .update(database_1.schema.sessions)
                    .set({ revoked: true })
                    .where((0, drizzle_orm_1.and)((0, drizzle_orm_1.eq)(database_1.schema.sessions.userId, userId), (0, drizzle_orm_1.eq)(database_1.schema.sessions.id, exceptSessionId ? sql `!= ${exceptSessionId}` : sql `IS NOT NULL`)));
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
            return { success: false, error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR } };
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
                sessionId: database_1.schema.sessions.id,
                createdAt: database_1.schema.sessions.createdAt,
                expiresAt: database_1.schema.sessions.expiresAt,
                refreshExpiresAt: database_1.schema.sessions.refreshExpiresAt,
                deviceName: database_1.schema.devices.name,
                deviceType: database_1.schema.devices.type,
                deviceOS: database_1.schema.devices.os,
                deviceBrowser: database_1.schema.devices.browser,
                deviceIsTrusted: database_1.schema.devices.isTrusted,
                deviceLastSeenAt: database_1.schema.devices.lastSeenAt,
                deviceIpAddress: database_1.schema.devices.ipAddress,
            })
                .from(database_1.schema.sessions)
                .leftJoin(database_1.schema.devices, (0, drizzle_orm_1.eq)(database_1.schema.sessions.id, database_1.schema.devices.userId))
                .where((0, drizzle_orm_1.and)((0, drizzle_orm_1.eq)(database_1.schema.sessions.userId, userId), (0, drizzle_orm_1.eq)(database_1.schema.sessions.revoked, false)));
            return {
                success: true,
                sessions: sessions.map(s => ({
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
            return { success: false, error: { code: 'INTERNAL_ERROR', message: constants_1.AUTH_CONSTANTS.ERROR_MESSAGES.INTERNAL_ERROR } };
        }
    },
    /**
     * Verifica se dispositivo é confiável
     */
    async isTrustedDevice(userId, deviceId) {
        const db = getDB();
        try {
            const devices = await db
                .select({ isTrusted: database_1.schema.devices.isTrusted, trustedUntil: database_1.schema.devices.trustedUntil })
                .from(database_1.schema.devices)
                .where((0, drizzle_orm_1.and)((0, drizzle_orm_1.eq)(database_1.schema.devices.id, deviceId), (0, drizzle_orm_1.eq)(database_1.schema.devices.userId, userId)))
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
// Helper para SQL (importar de drizzle-orm)
const sql = {
    not: (value) => value,
    ne: (col, val) => ({ col, val, op: '!=' }),
};
//# sourceMappingURL=session.service.js.map
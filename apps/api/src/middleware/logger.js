/**
 * Middleware de Logging de Requests
 *
 * SECURITY: Log estruturado SEM dados sensíveis
 * NUNCA logar: senhas, tokens, chaves, dados biométricos
 */
import { v4 as uuidv4 } from 'uuid';
export function requestLogger(req, res, next) {
    // Gerar ID único para este request (para tracing)
    req.requestId = req.headers['x-request-id'] || uuidv4();
    req.startTime = Date.now();
    // Adicionar requestId ao response header
    res.setHeader('X-Request-Id', req.requestId);
    // Capturar tempo de resposta
    res.on('finish', () => {
        const duration = Date.now() - req.startTime;
        // Log estruturado (sem dados sensíveis!)
        const logEntry = {
            timestamp: new Date().toISOString(),
            requestId: req.requestId,
            method: req.method,
            path: req.path,
            query: Object.keys(req.query).length > 0 ? '[PRESENT]' : '[ABSENT]',
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            userAgent: req.headers['user-agent'] ? '[PRESENT]' : '[ABSENT]',
            ip: req.ip || 'unknown',
        };
        // Logs diferentes por nível de severidade
        if (res.statusCode >= 500) {
            console.error('❌ [ERROR]', JSON.stringify(logEntry));
        }
        else if (res.statusCode >= 400) {
            console.warn('⚠️  [WARN]', JSON.stringify(logEntry));
        }
        else {
            console.log('📝 [INFO]', JSON.stringify(logEntry));
        }
    });
    next();
}
/**
 * Logger seguro para uso em serviços
 * SECURITY: Sanitiza dados antes de logar
 */
export function safeLog(level, message, data) {
    // Remover possíveis dados sensíveis
    const sanitizedData = sanitizeForLog(data || {});
    const logEntry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        ...sanitizedData,
    };
    switch (level) {
        case 'error':
            console.error('❌', JSON.stringify(logEntry));
            break;
        case 'warn':
            console.warn('⚠️ ', JSON.stringify(logEntry));
            break;
        default:
            console.log('📝', JSON.stringify(logEntry));
    }
}
/**
 * Sanitiza objeto para logging
 * SECURITY: Remove campos sensíveis
 */
function sanitizeForLog(data) {
    const sensitiveFields = [
        'password',
        'passwd',
        'pwd',
        'secret',
        'token',
        'accessToken',
        'refreshToken',
        'apiKey',
        'api_key',
        'privateKey',
        'encryptionKey',
        'mfaSecret',
        'recoveryCode',
        'creditCard',
        'cardNumber',
        'cvv',
        'ssn',
        'cpf',
        'cnpj',
    ];
    const sanitized = {};
    for (const [key, value] of Object.entries(data)) {
        const lowerKey = key.toLowerCase();
        if (sensitiveFields.some((field) => lowerKey.includes(field))) {
            sanitized[key] = '[REDACTED]';
        }
        else if (typeof value === 'object' && value !== null) {
            sanitized[key] = sanitizeForLog(value);
        }
        else {
            sanitized[key] = value;
        }
    }
    return sanitized;
}
//# sourceMappingURL=logger.js.map
/**
 * Middleware de Headers de Segurança Adicionais
 *
 * Complementa o helmet com headers específicos do ZERO
 */
export function securityHeaders(req, res, next) {
    // Prevenir clickjacking (além do helmet)
    res.setHeader('X-Frame-Options', 'DENY');
    // Prevenir MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // XSS Filter (legado, mas ainda útil)
    res.setHeader('X-XSS-Protection', '1; mode=block');
    // Referrer Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // Permissions Policy (antigo Feature Policy)
    res.setHeader('Permissions-Policy', [
        'accelerometer=()',
        'ambient-light-sensor=()',
        'autoplay=()',
        'battery=()',
        'camera=()',
        'cross-origin-isolated=()',
        'display-capture=()',
        'document-domain=()',
        'encrypted-media=()',
        'execution-while-not-rendered=()',
        'execution-while-out-of-viewport=()',
        'fullscreen=()',
        'geolocation=()',
        'gyroscope=()',
        'keyboard-map=()',
        'magnetometer=()',
        'microphone=()',
        'midi=()',
        'navigation-override=()',
        'payment=()',
        'picture-in-picture=()',
        'publickey-credentials-get=()',
        'screen-wake-lock=()',
        'sync-xhr=()',
        'usb=()',
        'web-share=()',
        'xr-spatial-tracking=()',
    ].join(', '));
    // Cache control para dados sensíveis
    if (req.path.startsWith('/api/')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
    }
    // Remover header que revela tecnologia
    res.removeHeader('X-Powered-By');
    next();
}
//# sourceMappingURL=security.js.map
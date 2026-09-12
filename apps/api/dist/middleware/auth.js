/**
 * Middleware de Autenticação
 *
 * RESPONSABILIDADES:
 * - Validar JWT access token
 * - Extrair sessão do request
 * - Proteger rotas que exigem autenticação
 * - Renovar tokens quando necessário
 */
import { verifyJWT } from '@zero/auth';
/**
 * Extrai sessão do request (JWT ou cookie)
 */
export function getSessionFromRequest(req) {
    // Tentar extrair do header Authorization
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        try {
            const payload = verifyJWT(token, 'access');
            return {
                userId: payload.userId,
                sessionId: payload.sessionId,
                deviceId: payload.deviceId,
                createdAt: new Date(payload.iat * 1000),
            };
        }
        catch {
            // Token inválido
        }
    }
    // Tentar extrair do cookie
    const accessToken = req.cookies?.accessToken;
    if (accessToken) {
        try {
            const payload = verifyJWT(accessToken, 'access');
            return {
                userId: payload.userId,
                sessionId: payload.sessionId,
                deviceId: payload.deviceId,
                createdAt: new Date(payload.iat * 1000),
            };
        }
        catch {
            // Token inválido
        }
    }
    return null;
}
/**
 * Middleware que exige autenticação
 * Adiciona auth ao request se válido
 */
export function requireAuth(req, res, next) {
    const session = getSessionFromRequest(req);
    if (!session) {
        res.status(401).json({
            error: 'Unauthorized',
            message: 'Autenticação necessária',
        });
        return;
    }
    // Adicionar informações de auth ao request
    req.auth = session;
    next();
}
/**
 * Middleware para operações sensíveis (step-up auth)
 * Pode exigir re-autenticação recente
 */
export function requireRecentAuth(maxAgeMs = 5 * 60 * 1000) {
    return (req, res, next) => {
        const session = getSessionFromRequest(req);
        if (!session) {
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Autenticação necessária',
            });
            return;
        }
        // Verificar se a sessão é recente o suficiente
        const now = Date.now();
        const sessionAge = now - session.createdAt.getTime();
        if (sessionAge > maxAgeMs) {
            res.status(403).json({
                error: 'Authentication Required',
                message: 'Re-autenticação necessária para esta operação',
                requiresStepUp: true,
            });
            return;
        }
        req.auth = session;
        next();
    };
}
/**
 * Middleware opcional de autenticação
 * Adiciona auth se presente, mas não falha se ausente
 */
export function optionalAuth(req, res, next) {
    const session = getSessionFromRequest(req);
    if (session) {
        req.auth = session;
    }
    next();
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9taWRkbGV3YXJlL2F1dGgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7Ozs7Ozs7O0dBUUc7QUFHSCxPQUFPLEVBQUUsU0FBUyxFQUFFLE1BQU0sWUFBWSxDQUFDO0FBWXZDOztHQUVHO0FBQ0gsTUFBTSxVQUFVLHFCQUFxQixDQUFDLEdBQVk7SUFNaEQseUNBQXlDO0lBQ3pDLE1BQU0sVUFBVSxHQUFHLEdBQUcsQ0FBQyxPQUFPLENBQUMsYUFBYSxDQUFDO0lBQzdDLElBQUksVUFBVSxJQUFJLFVBQVUsQ0FBQyxVQUFVLENBQUMsU0FBUyxDQUFDLEVBQUUsQ0FBQztRQUNuRCxNQUFNLEtBQUssR0FBRyxVQUFVLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBQ3RDLElBQUksQ0FBQztZQUNILE1BQU0sT0FBTyxHQUFHLFNBQVMsQ0FBQyxLQUFLLEVBQUUsUUFBUSxDQUFDLENBQUM7WUFDM0MsT0FBTztnQkFDTCxNQUFNLEVBQUUsT0FBTyxDQUFDLE1BQU07Z0JBQ3RCLFNBQVMsRUFBRSxPQUFPLENBQUMsU0FBUztnQkFDNUIsUUFBUSxFQUFFLE9BQU8sQ0FBQyxRQUFRO2dCQUMxQixTQUFTLEVBQUUsSUFBSSxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsR0FBRyxJQUFJLENBQUM7YUFDeEMsQ0FBQztRQUNKLENBQUM7UUFBQyxNQUFNLENBQUM7WUFDUCxpQkFBaUI7UUFDbkIsQ0FBQztJQUNILENBQUM7SUFFRCwyQkFBMkI7SUFDM0IsTUFBTSxXQUFXLEdBQUcsR0FBRyxDQUFDLE9BQU8sRUFBRSxXQUFXLENBQUM7SUFDN0MsSUFBSSxXQUFXLEVBQUUsQ0FBQztRQUNoQixJQUFJLENBQUM7WUFDSCxNQUFNLE9BQU8sR0FBRyxTQUFTLENBQUMsV0FBVyxFQUFFLFFBQVEsQ0FBQyxDQUFDO1lBQ2pELE9BQU87Z0JBQ0wsTUFBTSxFQUFFLE9BQU8sQ0FBQyxNQUFNO2dCQUN0QixTQUFTLEVBQUUsT0FBTyxDQUFDLFNBQVM7Z0JBQzVCLFFBQVEsRUFBRSxPQUFPLENBQUMsUUFBUTtnQkFDMUIsU0FBUyxFQUFFLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLEdBQUcsSUFBSSxDQUFDO2FBQ3hDLENBQUM7UUFDSixDQUFDO1FBQUMsTUFBTSxDQUFDO1lBQ1AsaUJBQWlCO1FBQ25CLENBQUM7SUFDSCxDQUFDO0lBRUQsT0FBTyxJQUFJLENBQUM7QUFDZCxDQUFDO0FBRUQ7OztHQUdHO0FBQ0gsTUFBTSxVQUFVLFdBQVcsQ0FDekIsR0FBeUIsRUFDekIsR0FBYSxFQUNiLElBQWtCO0lBRWxCLE1BQU0sT0FBTyxHQUFHLHFCQUFxQixDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBRTNDLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQztRQUNiLEdBQUcsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDO1lBQ25CLEtBQUssRUFBRSxjQUFjO1lBQ3JCLE9BQU8sRUFBRSx5QkFBeUI7U0FDbkMsQ0FBQyxDQUFDO1FBQ0gsT0FBTztJQUNULENBQUM7SUFFRCwyQ0FBMkM7SUFDM0MsR0FBRyxDQUFDLElBQUksR0FBRyxPQUFPLENBQUM7SUFFbkIsSUFBSSxFQUFFLENBQUM7QUFDVCxDQUFDO0FBRUQ7OztHQUdHO0FBQ0gsTUFBTSxVQUFVLGlCQUFpQixDQUFDLFdBQW1CLENBQUMsR0FBRyxFQUFFLEdBQUcsSUFBSTtJQUNoRSxPQUFPLENBQUMsR0FBeUIsRUFBRSxHQUFhLEVBQUUsSUFBa0IsRUFBRSxFQUFFO1FBQ3RFLE1BQU0sT0FBTyxHQUFHLHFCQUFxQixDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBRTNDLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQztZQUNiLEdBQUcsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDO2dCQUNuQixLQUFLLEVBQUUsY0FBYztnQkFDckIsT0FBTyxFQUFFLHlCQUF5QjthQUNuQyxDQUFDLENBQUM7WUFDSCxPQUFPO1FBQ1QsQ0FBQztRQUVELCtDQUErQztRQUMvQyxNQUFNLEdBQUcsR0FBRyxJQUFJLENBQUMsR0FBRyxFQUFFLENBQUM7UUFDdkIsTUFBTSxVQUFVLEdBQUcsR0FBRyxHQUFHLE9BQU8sQ0FBQyxTQUFTLENBQUMsT0FBTyxFQUFFLENBQUM7UUFFckQsSUFBSSxVQUFVLEdBQUcsUUFBUSxFQUFFLENBQUM7WUFDMUIsR0FBRyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUM7Z0JBQ25CLEtBQUssRUFBRSx5QkFBeUI7Z0JBQ2hDLE9BQU8sRUFBRSwrQ0FBK0M7Z0JBQ3hELGNBQWMsRUFBRSxJQUFJO2FBQ3JCLENBQUMsQ0FBQztZQUNILE9BQU87UUFDVCxDQUFDO1FBRUQsR0FBRyxDQUFDLElBQUksR0FBRyxPQUFPLENBQUM7UUFDbkIsSUFBSSxFQUFFLENBQUM7SUFDVCxDQUFDLENBQUM7QUFDSixDQUFDO0FBRUQ7OztHQUdHO0FBQ0gsTUFBTSxVQUFVLFlBQVksQ0FDMUIsR0FBeUIsRUFDekIsR0FBYSxFQUNiLElBQWtCO0lBRWxCLE1BQU0sT0FBTyxHQUFHLHFCQUFxQixDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBRTNDLElBQUksT0FBTyxFQUFFLENBQUM7UUFDWixHQUFHLENBQUMsSUFBSSxHQUFHLE9BQU8sQ0FBQztJQUNyQixDQUFDO0lBRUQsSUFBSSxFQUFFLENBQUM7QUFDVCxDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBNaWRkbGV3YXJlIGRlIEF1dGVudGljYcOnw6NvXG4gKiBcbiAqIFJFU1BPTlNBQklMSURBREVTOlxuICogLSBWYWxpZGFyIEpXVCBhY2Nlc3MgdG9rZW5cbiAqIC0gRXh0cmFpciBzZXNzw6NvIGRvIHJlcXVlc3RcbiAqIC0gUHJvdGVnZXIgcm90YXMgcXVlIGV4aWdlbSBhdXRlbnRpY2HDp8Ojb1xuICogLSBSZW5vdmFyIHRva2VucyBxdWFuZG8gbmVjZXNzw6FyaW9cbiAqL1xuXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSwgTmV4dEZ1bmN0aW9uIH0gZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgeyB2ZXJpZnlKV1QgfSBmcm9tICdAemVyby9hdXRoJztcbmltcG9ydCB0eXBlIHsgSldUUGF5bG9hZCB9IGZyb20gJ0B6ZXJvL2F1dGgnO1xuXG5leHBvcnQgaW50ZXJmYWNlIEF1dGhlbnRpY2F0ZWRSZXF1ZXN0IGV4dGVuZHMgUmVxdWVzdCB7XG4gIGF1dGg/OiB7XG4gICAgdXNlcklkOiBzdHJpbmc7XG4gICAgc2Vzc2lvbklkOiBzdHJpbmc7XG4gICAgZGV2aWNlSWQ6IHN0cmluZztcbiAgICBwYXlsb2FkOiBKV1RQYXlsb2FkO1xuICB9O1xufVxuXG4vKipcbiAqIEV4dHJhaSBzZXNzw6NvIGRvIHJlcXVlc3QgKEpXVCBvdSBjb29raWUpXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRTZXNzaW9uRnJvbVJlcXVlc3QocmVxOiBSZXF1ZXN0KToge1xuICB1c2VySWQ6IHN0cmluZztcbiAgc2Vzc2lvbklkOiBzdHJpbmc7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGNyZWF0ZWRBdDogRGF0ZTtcbn0gfCBudWxsIHtcbiAgLy8gVGVudGFyIGV4dHJhaXIgZG8gaGVhZGVyIEF1dGhvcml6YXRpb25cbiAgY29uc3QgYXV0aEhlYWRlciA9IHJlcS5oZWFkZXJzLmF1dGhvcml6YXRpb247XG4gIGlmIChhdXRoSGVhZGVyICYmIGF1dGhIZWFkZXIuc3RhcnRzV2l0aCgnQmVhcmVyICcpKSB7XG4gICAgY29uc3QgdG9rZW4gPSBhdXRoSGVhZGVyLnN1YnN0cmluZyg3KTtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcGF5bG9hZCA9IHZlcmlmeUpXVCh0b2tlbiwgJ2FjY2VzcycpO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgdXNlcklkOiBwYXlsb2FkLnVzZXJJZCxcbiAgICAgICAgc2Vzc2lvbklkOiBwYXlsb2FkLnNlc3Npb25JZCxcbiAgICAgICAgZGV2aWNlSWQ6IHBheWxvYWQuZGV2aWNlSWQsXG4gICAgICAgIGNyZWF0ZWRBdDogbmV3IERhdGUocGF5bG9hZC5pYXQgKiAxMDAwKSxcbiAgICAgIH07XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBUb2tlbiBpbnbDoWxpZG9cbiAgICB9XG4gIH1cblxuICAvLyBUZW50YXIgZXh0cmFpciBkbyBjb29raWVcbiAgY29uc3QgYWNjZXNzVG9rZW4gPSByZXEuY29va2llcz8uYWNjZXNzVG9rZW47XG4gIGlmIChhY2Nlc3NUb2tlbikge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBwYXlsb2FkID0gdmVyaWZ5SldUKGFjY2Vzc1Rva2VuLCAnYWNjZXNzJyk7XG4gICAgICByZXR1cm4ge1xuICAgICAgICB1c2VySWQ6IHBheWxvYWQudXNlcklkLFxuICAgICAgICBzZXNzaW9uSWQ6IHBheWxvYWQuc2Vzc2lvbklkLFxuICAgICAgICBkZXZpY2VJZDogcGF5bG9hZC5kZXZpY2VJZCxcbiAgICAgICAgY3JlYXRlZEF0OiBuZXcgRGF0ZShwYXlsb2FkLmlhdCAqIDEwMDApLFxuICAgICAgfTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIFRva2VuIGludsOhbGlkb1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBudWxsO1xufVxuXG4vKipcbiAqIE1pZGRsZXdhcmUgcXVlIGV4aWdlIGF1dGVudGljYcOnw6NvXG4gKiBBZGljaW9uYSBhdXRoIGFvIHJlcXVlc3Qgc2UgdsOhbGlkb1xuICovXG5leHBvcnQgZnVuY3Rpb24gcmVxdWlyZUF1dGgoXG4gIHJlcTogQXV0aGVudGljYXRlZFJlcXVlc3QsXG4gIHJlczogUmVzcG9uc2UsXG4gIG5leHQ6IE5leHRGdW5jdGlvblxuKTogdm9pZCB7XG4gIGNvbnN0IHNlc3Npb24gPSBnZXRTZXNzaW9uRnJvbVJlcXVlc3QocmVxKTtcblxuICBpZiAoIXNlc3Npb24pIHtcbiAgICByZXMuc3RhdHVzKDQwMSkuanNvbih7XG4gICAgICBlcnJvcjogJ1VuYXV0aG9yaXplZCcsXG4gICAgICBtZXNzYWdlOiAnQXV0ZW50aWNhw6fDo28gbmVjZXNzw6FyaWEnLFxuICAgIH0pO1xuICAgIHJldHVybjtcbiAgfVxuXG4gIC8vIEFkaWNpb25hciBpbmZvcm1hw6fDtWVzIGRlIGF1dGggYW8gcmVxdWVzdFxuICByZXEuYXV0aCA9IHNlc3Npb247XG5cbiAgbmV4dCgpO1xufVxuXG4vKipcbiAqIE1pZGRsZXdhcmUgcGFyYSBvcGVyYcOnw7VlcyBzZW5zw612ZWlzIChzdGVwLXVwIGF1dGgpXG4gKiBQb2RlIGV4aWdpciByZS1hdXRlbnRpY2HDp8OjbyByZWNlbnRlXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiByZXF1aXJlUmVjZW50QXV0aChtYXhBZ2VNczogbnVtYmVyID0gNSAqIDYwICogMTAwMCkge1xuICByZXR1cm4gKHJlcTogQXV0aGVudGljYXRlZFJlcXVlc3QsIHJlczogUmVzcG9uc2UsIG5leHQ6IE5leHRGdW5jdGlvbikgPT4ge1xuICAgIGNvbnN0IHNlc3Npb24gPSBnZXRTZXNzaW9uRnJvbVJlcXVlc3QocmVxKTtcblxuICAgIGlmICghc2Vzc2lvbikge1xuICAgICAgcmVzLnN0YXR1cyg0MDEpLmpzb24oe1xuICAgICAgICBlcnJvcjogJ1VuYXV0aG9yaXplZCcsXG4gICAgICAgIG1lc3NhZ2U6ICdBdXRlbnRpY2HDp8OjbyBuZWNlc3PDoXJpYScsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBWZXJpZmljYXIgc2UgYSBzZXNzw6NvIMOpIHJlY2VudGUgbyBzdWZpY2llbnRlXG4gICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgICBjb25zdCBzZXNzaW9uQWdlID0gbm93IC0gc2Vzc2lvbi5jcmVhdGVkQXQuZ2V0VGltZSgpO1xuXG4gICAgaWYgKHNlc3Npb25BZ2UgPiBtYXhBZ2VNcykge1xuICAgICAgcmVzLnN0YXR1cyg0MDMpLmpzb24oe1xuICAgICAgICBlcnJvcjogJ0F1dGhlbnRpY2F0aW9uIFJlcXVpcmVkJyxcbiAgICAgICAgbWVzc2FnZTogJ1JlLWF1dGVudGljYcOnw6NvIG5lY2Vzc8OhcmlhIHBhcmEgZXN0YSBvcGVyYcOnw6NvJyxcbiAgICAgICAgcmVxdWlyZXNTdGVwVXA6IHRydWUsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICByZXEuYXV0aCA9IHNlc3Npb247XG4gICAgbmV4dCgpO1xuICB9O1xufVxuXG4vKipcbiAqIE1pZGRsZXdhcmUgb3BjaW9uYWwgZGUgYXV0ZW50aWNhw6fDo29cbiAqIEFkaWNpb25hIGF1dGggc2UgcHJlc2VudGUsIG1hcyBuw6NvIGZhbGhhIHNlIGF1c2VudGVcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIG9wdGlvbmFsQXV0aChcbiAgcmVxOiBBdXRoZW50aWNhdGVkUmVxdWVzdCxcbiAgcmVzOiBSZXNwb25zZSxcbiAgbmV4dDogTmV4dEZ1bmN0aW9uXG4pOiB2b2lkIHtcbiAgY29uc3Qgc2Vzc2lvbiA9IGdldFNlc3Npb25Gcm9tUmVxdWVzdChyZXEpO1xuXG4gIGlmIChzZXNzaW9uKSB7XG4gICAgcmVxLmF1dGggPSBzZXNzaW9uO1xuICB9XG5cbiAgbmV4dCgpO1xufVxuIl19
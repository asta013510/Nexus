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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2VjdXJpdHkuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvbWlkZGxld2FyZS9zZWN1cml0eS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7OztHQUlHO0FBSUgsTUFBTSxVQUFVLGVBQWUsQ0FBQyxHQUFZLEVBQUUsR0FBYSxFQUFFLElBQWtCO0lBQzdFLHlDQUF5QztJQUN6QyxHQUFHLENBQUMsU0FBUyxDQUFDLGlCQUFpQixFQUFFLE1BQU0sQ0FBQyxDQUFDO0lBRXpDLDhCQUE4QjtJQUM5QixHQUFHLENBQUMsU0FBUyxDQUFDLHdCQUF3QixFQUFFLFNBQVMsQ0FBQyxDQUFDO0lBRW5ELHNDQUFzQztJQUN0QyxHQUFHLENBQUMsU0FBUyxDQUFDLGtCQUFrQixFQUFFLGVBQWUsQ0FBQyxDQUFDO0lBRW5ELGtCQUFrQjtJQUNsQixHQUFHLENBQUMsU0FBUyxDQUFDLGlCQUFpQixFQUFFLGlDQUFpQyxDQUFDLENBQUM7SUFFcEUsNkNBQTZDO0lBQzdDLEdBQUcsQ0FBQyxTQUFTLENBQ1gsb0JBQW9CLEVBQ3BCO1FBQ0Usa0JBQWtCO1FBQ2xCLHlCQUF5QjtRQUN6QixhQUFhO1FBQ2IsWUFBWTtRQUNaLFdBQVc7UUFDWCwwQkFBMEI7UUFDMUIsb0JBQW9CO1FBQ3BCLG9CQUFvQjtRQUNwQixvQkFBb0I7UUFDcEIsaUNBQWlDO1FBQ2pDLG9DQUFvQztRQUNwQyxlQUFlO1FBQ2YsZ0JBQWdCO1FBQ2hCLGNBQWM7UUFDZCxpQkFBaUI7UUFDakIsaUJBQWlCO1FBQ2pCLGVBQWU7UUFDZixTQUFTO1FBQ1Qsd0JBQXdCO1FBQ3hCLFlBQVk7UUFDWix1QkFBdUI7UUFDdkIsOEJBQThCO1FBQzlCLHFCQUFxQjtRQUNyQixhQUFhO1FBQ2IsUUFBUTtRQUNSLGNBQWM7UUFDZCx3QkFBd0I7S0FDekIsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQ2IsQ0FBQztJQUVGLHFDQUFxQztJQUNyQyxJQUFJLEdBQUcsQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUM7UUFDakMsR0FBRyxDQUFDLFNBQVMsQ0FBQyxlQUFlLEVBQUUsdURBQXVELENBQUMsQ0FBQztRQUN4RixHQUFHLENBQUMsU0FBUyxDQUFDLFFBQVEsRUFBRSxVQUFVLENBQUMsQ0FBQztRQUNwQyxHQUFHLENBQUMsU0FBUyxDQUFDLFNBQVMsRUFBRSxHQUFHLENBQUMsQ0FBQztJQUNoQyxDQUFDO0lBRUQsdUNBQXVDO0lBQ3ZDLEdBQUcsQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLENBQUM7SUFFakMsSUFBSSxFQUFFLENBQUM7QUFDVCxDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBNaWRkbGV3YXJlIGRlIEhlYWRlcnMgZGUgU2VndXJhbsOnYSBBZGljaW9uYWlzXG4gKiBcbiAqIENvbXBsZW1lbnRhIG8gaGVsbWV0IGNvbSBoZWFkZXJzIGVzcGVjw61maWNvcyBkbyBaRVJPXG4gKi9cblxuaW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UsIE5leHRGdW5jdGlvbiB9IGZyb20gJ2V4cHJlc3MnO1xuXG5leHBvcnQgZnVuY3Rpb24gc2VjdXJpdHlIZWFkZXJzKHJlcTogUmVxdWVzdCwgcmVzOiBSZXNwb25zZSwgbmV4dDogTmV4dEZ1bmN0aW9uKTogdm9pZCB7XG4gIC8vIFByZXZlbmlyIGNsaWNramFja2luZyAoYWzDqW0gZG8gaGVsbWV0KVxuICByZXMuc2V0SGVhZGVyKCdYLUZyYW1lLU9wdGlvbnMnLCAnREVOWScpO1xuICBcbiAgLy8gUHJldmVuaXIgTUlNRSB0eXBlIHNuaWZmaW5nXG4gIHJlcy5zZXRIZWFkZXIoJ1gtQ29udGVudC1UeXBlLU9wdGlvbnMnLCAnbm9zbmlmZicpO1xuICBcbiAgLy8gWFNTIEZpbHRlciAobGVnYWRvLCBtYXMgYWluZGEgw7p0aWwpXG4gIHJlcy5zZXRIZWFkZXIoJ1gtWFNTLVByb3RlY3Rpb24nLCAnMTsgbW9kZT1ibG9jaycpO1xuICBcbiAgLy8gUmVmZXJyZXIgUG9saWN5XG4gIHJlcy5zZXRIZWFkZXIoJ1JlZmVycmVyLVBvbGljeScsICdzdHJpY3Qtb3JpZ2luLXdoZW4tY3Jvc3Mtb3JpZ2luJyk7XG4gIFxuICAvLyBQZXJtaXNzaW9ucyBQb2xpY3kgKGFudGlnbyBGZWF0dXJlIFBvbGljeSlcbiAgcmVzLnNldEhlYWRlcihcbiAgICAnUGVybWlzc2lvbnMtUG9saWN5JyxcbiAgICBbXG4gICAgICAnYWNjZWxlcm9tZXRlcj0oKScsXG4gICAgICAnYW1iaWVudC1saWdodC1zZW5zb3I9KCknLFxuICAgICAgJ2F1dG9wbGF5PSgpJyxcbiAgICAgICdiYXR0ZXJ5PSgpJyxcbiAgICAgICdjYW1lcmE9KCknLFxuICAgICAgJ2Nyb3NzLW9yaWdpbi1pc29sYXRlZD0oKScsXG4gICAgICAnZGlzcGxheS1jYXB0dXJlPSgpJyxcbiAgICAgICdkb2N1bWVudC1kb21haW49KCknLFxuICAgICAgJ2VuY3J5cHRlZC1tZWRpYT0oKScsXG4gICAgICAnZXhlY3V0aW9uLXdoaWxlLW5vdC1yZW5kZXJlZD0oKScsXG4gICAgICAnZXhlY3V0aW9uLXdoaWxlLW91dC1vZi12aWV3cG9ydD0oKScsXG4gICAgICAnZnVsbHNjcmVlbj0oKScsXG4gICAgICAnZ2VvbG9jYXRpb249KCknLFxuICAgICAgJ2d5cm9zY29wZT0oKScsXG4gICAgICAna2V5Ym9hcmQtbWFwPSgpJyxcbiAgICAgICdtYWduZXRvbWV0ZXI9KCknLFxuICAgICAgJ21pY3JvcGhvbmU9KCknLFxuICAgICAgJ21pZGk9KCknLFxuICAgICAgJ25hdmlnYXRpb24tb3ZlcnJpZGU9KCknLFxuICAgICAgJ3BheW1lbnQ9KCknLFxuICAgICAgJ3BpY3R1cmUtaW4tcGljdHVyZT0oKScsXG4gICAgICAncHVibGlja2V5LWNyZWRlbnRpYWxzLWdldD0oKScsXG4gICAgICAnc2NyZWVuLXdha2UtbG9jaz0oKScsXG4gICAgICAnc3luYy14aHI9KCknLFxuICAgICAgJ3VzYj0oKScsXG4gICAgICAnd2ViLXNoYXJlPSgpJyxcbiAgICAgICd4ci1zcGF0aWFsLXRyYWNraW5nPSgpJyxcbiAgICBdLmpvaW4oJywgJylcbiAgKTtcbiAgXG4gIC8vIENhY2hlIGNvbnRyb2wgcGFyYSBkYWRvcyBzZW5zw612ZWlzXG4gIGlmIChyZXEucGF0aC5zdGFydHNXaXRoKCcvYXBpLycpKSB7XG4gICAgcmVzLnNldEhlYWRlcignQ2FjaGUtQ29udHJvbCcsICduby1zdG9yZSwgbm8tY2FjaGUsIG11c3QtcmV2YWxpZGF0ZSwgcHJveHktcmV2YWxpZGF0ZScpO1xuICAgIHJlcy5zZXRIZWFkZXIoJ1ByYWdtYScsICduby1jYWNoZScpO1xuICAgIHJlcy5zZXRIZWFkZXIoJ0V4cGlyZXMnLCAnMCcpO1xuICB9XG4gIFxuICAvLyBSZW1vdmVyIGhlYWRlciBxdWUgcmV2ZWxhIHRlY25vbG9naWFcbiAgcmVzLnJlbW92ZUhlYWRlcignWC1Qb3dlcmVkLUJ5Jyk7XG4gIFxuICBuZXh0KCk7XG59XG4iXX0=
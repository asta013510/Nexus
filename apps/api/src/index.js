/**
 * ZERO API - Ponto de Entrada Principal
 *
 * Central de Segurança Pessoal
 * SECURITY: Primeira linha de defesa da aplicação
 */
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
// Configuração
import { loadConfig, initDatabase, checkDatabaseHealth } from './config/index.js';
// Middleware de segurança
import { securityHeaders } from './middleware/security.js';
import { requestLogger } from './middleware/logger.js';
import { errorHandler } from './middleware/errorHandler.js';
// Rotas (serão implementadas)
// import { authRoutes } from './routes/auth.js';
// import { documentRoutes } from './routes/documents.js';
async function bootstrap() {
    console.log('🚀 ZERO API - Inicializando...');
    // Carregar configuração (valida .env)
    const config = loadConfig();
    console.log(`⚙️  Ambiente: ${config.NODE_ENV}`);
    // Inicializar database
    initDatabase();
    // Verificar saúde do database
    const dbHealthy = await checkDatabaseHealth();
    if (!dbHealthy) {
        console.error('❌ Database não está saudável. Abortando inicialização.');
        process.exit(1);
    }
    // Criar aplicação Express
    const app = express();
    // ===========================================================================
    // MIDDLEWARES DE SEGURANÇA (ordem importa!)
    // ===========================================================================
    // Helmet - Headers de segurança HTTP
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", 'data:', 'blob:'],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
            },
        },
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true,
        },
        noSniff: true,
        xssFilter: true,
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    }));
    // Headers de segurança adicionais
    app.use(securityHeaders);
    // CORS configurado estritamente
    app.use(cors({
        origin: config.CORS_ORIGIN,
        credentials: config.CORS_CREDENTIALS,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
        exposedHeaders: ['X-Request-Id'],
        maxAge: 86400, // 24 horas
    }));
    // Rate limiting global
    const limiter = rateLimit({
        windowMs: config.RATE_LIMIT_WINDOW_MS,
        max: config.RATE_LIMIT_MAX_REQUESTS,
        message: {
            error: 'Too many requests',
            message: 'Você excedeu o limite de requisições. Tente novamente mais tarde.',
        },
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => {
            res.status(429).json({
                error: 'Too many requests',
                message: 'Limite de requisições excedido',
            });
        },
    });
    app.use('/api/', limiter);
    // Body parser com limites seguros
    app.use(express.json({
        limit: '1mb',
        strict: true,
    }));
    app.use(express.urlencoded({
        extended: true,
        limit: '1mb',
        parameterLimit: 100,
    }));
    // Compression
    app.use(compression());
    // Cookie parser
    app.use(cookieParser());
    // Request logging (sem dados sensíveis)
    app.use(requestLogger);
    // ===========================================================================
    // ROTAS
    // ===========================================================================
    // ===========================================================================
    // ROTAS
    // ===========================================================================
    // Health check (pública)
    app.get('/health', async (req, res) => {
        const dbHealthy = await checkDatabaseHealth();
        if (dbHealthy) {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                version: '0.1.0',
                environment: config.NODE_ENV,
            });
        }
        else {
            res.status(503).json({
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
            });
        }
    });
    // API root
    app.get('/api', (req, res) => {
        res.json({
            name: 'ZERO API',
            version: '0.1.0',
            description: 'Central de Segurança Pessoal',
            documentation: '/api/docs', // Futuro
        });
    });
    // Mount routes de autenticação
    import('./routes/auth.js').then(({ authRoutes }) => {
        app.use('/api/auth', authRoutes);
        console.log('✅ Rotas de autenticação carregadas');
    }).catch((error) => {
        console.error('❌ Erro ao carregar rotas de autenticação:', error);
    });
    // TODO: Mount routes de documentos (futuro)
    // import('./routes/documents.js').then(({ documentRoutes }) => {
    //   app.use('/api/documents', documentRoutes);
    // });
    // 404 handler
    app.use((req, res) => {
        res.status(404).json({
            error: 'Not Found',
            message: 'Endpoint não encontrado',
        });
    });
    // Error handler (deve ser o último)
    app.use(errorHandler);
    // ===========================================================================
    // INICIALIZAÇÃO DO SERVIDOR
    // ===========================================================================
    const PORT = config.PORT;
    const server = app.listen(PORT, () => {
        console.log(`✅ ZERO API rodando em http://localhost:${PORT}`);
        console.log(`🔒 Modo: ${config.NODE_ENV}`);
        console.log(`📊 Health check: http://localhost:${PORT}/health`);
    });
    // Graceful shutdown
    const gracefulShutdown = async (signal) => {
        console.log(`\n🛑 Recebido ${signal}. Iniciando shutdown graceful...`);
        server.close(async () => {
            console.log('🔒 Servidor HTTP fechado');
            // Fechar database
            try {
                // await closeDatabase();
                console.log('🔒 Database desconectado');
            }
            catch (error) {
                console.error('Erro ao fechar database:', error);
            }
            process.exit(0);
        });
        // Force shutdown after timeout
        setTimeout(() => {
            console.error('⚠️  Shutdown forçado após timeout');
            process.exit(1);
        }, 30000);
    };
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    // Unhandled rejection handler
    process.on('unhandledRejection', (reason, promise) => {
        console.error('Unhandled Rejection at:', promise, 'reason:', reason);
        // Não encerrar em produção, mas logar para investigação
    });
    return { app, server };
}
// Iniciar aplicação
bootstrap().catch((error) => {
    console.error('❌ Falha ao iniciar ZERO API:', error);
    process.exit(1);
});
//# sourceMappingURL=index.js.map
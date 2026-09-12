import { Router } from 'express';
import { FacialBiometricService, LivenessDetectionService } from '@zero/auth';
import { AuthMiddleware } from '../middleware/auth.js';
import { AuditService } from '@zero/auth';
const router = Router();
const authMiddleware = new AuthMiddleware();
const facialService = new FacialBiometricService();
const livenessService = new LivenessDetectionService();
const auditService = new AuditService();
/**
 * POST /biometric/facial/enroll
 * Cadastrar template biométrico facial
 */
router.post('/facial/enroll', authMiddleware.requireAuth, authMiddleware.requireStepUp, async (req, res) => {
    try {
        const userId = req.user?.userId;
        if (!userId)
            throw new Error('User ID not found');
        const { embedding, livenessData } = req.body;
        if (!embedding || !Array.isArray(embedding)) {
            return res.status(400).json({ error: 'Invalid facial embedding' });
        }
        // Validar liveness detection
        const livenessResult = await livenessService.validateLiveness(livenessData);
        if (!livenessResult.isLive) {
            // Auditoria de falha de liveness
            await auditService.log({
                userId,
                action: 'BIOMETRIC_LIVENESS_FAILED',
                entityType: 'user',
                entityId: userId,
                metadata: { reason: livenessResult.reason },
                ipAddress: req.ip,
                userAgent: req.get('user-agent'),
            });
            return res.status(400).json({
                error: 'Liveness detection failed',
                reason: livenessResult.reason
            });
        }
        // Salvar template biométrico (hash irreversível)
        const result = await facialService.enroll(userId, embedding);
        // Auditoria
        await auditService.log({
            userId,
            action: 'BIOMETRIC_FACIAL_ENROLLED',
            entityType: 'user',
            entityId: userId,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
        });
        res.json({
            success: true,
            message: 'Facial biometric enrolled successfully',
            data: { enrolledAt: result.enrolledAt }
        });
    }
    catch (error) {
        if (error.message === 'User already has facial biometric enrolled') {
            return res.status(409).json({ error: error.message });
        }
        console.error('Facial enroll error:', error);
        res.status(500).json({ error: 'Failed to enroll facial biometric', message: error.message });
    }
});
/**
 * POST /biometric/facial/verify
 * Verificar identidade via biometria facial
 */
router.post('/facial/verify', async (req, res) => {
    try {
        const { embedding, livenessData, email } = req.body;
        if (!embedding || !Array.isArray(embedding) || !email) {
            return res.status(400).json({ error: 'Invalid request data' });
        }
        // Validar liveness primeiro
        const livenessResult = await livenessService.validateLiveness(livenessData);
        if (!livenessResult.isLive) {
            // Tentativa de fraude - auditoria crítica
            const user = await facialService.findUserByEmail(email);
            if (user) {
                await auditService.log({
                    userId: user.id,
                    action: 'BIOMETRIC_SPOOFING_ATTEMPTED',
                    entityType: 'user',
                    entityId: user.id,
                    metadata: { reason: livenessResult.reason, attackType: 'liveness_bypass' },
                    ipAddress: req.ip,
                    userAgent: req.get('user-agent'),
                    severity: 'critical',
                });
            }
            return res.status(400).json({
                error: 'Liveness detection failed',
                reason: livenessResult.reason
            });
        }
        // Verificar contra templates armazenados
        const result = await facialService.verify(email, embedding);
        if (!result.match) {
            // Falha de verificação
            if (result.userId) {
                await auditService.log({
                    userId: result.userId,
                    action: 'BIOMETRIC_VERIFICATION_FAILED',
                    entityType: 'user',
                    entityId: result.userId,
                    metadata: { confidence: result.confidence },
                    ipAddress: req.ip,
                    userAgent: req.get('user-agent'),
                });
            }
            return res.status(401).json({
                error: 'Facial verification failed',
                confidence: result.confidence
            });
        }
        // Sucesso - gerar token temporário para login
        const token = await facialService.generateBiometricToken(result.userId);
        // Auditoria
        await auditService.log({
            userId: result.userId,
            action: 'BIOMETRIC_VERIFICATION_SUCCESS',
            entityType: 'user',
            entityId: result.userId,
            metadata: { confidence: result.confidence },
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
        });
        res.json({
            success: true,
            message: 'Facial verification successful',
            data: {
                biometricToken: token,
                expiresIn: 300 // 5 minutos
            }
        });
    }
    catch (error) {
        console.error('Facial verify error:', error);
        res.status(500).json({ error: 'Failed to verify facial biometric', message: error.message });
    }
});
/**
 * POST /biometric/facial/liveness
 * Teste standalone de liveness detection
 */
router.post('/facial/liveness', async (req, res) => {
    try {
        const { livenessData } = req.body;
        if (!livenessData) {
            return res.status(400).json({ error: 'Liveness data required' });
        }
        const result = await livenessService.validateLiveness(livenessData);
        res.json({
            success: true,
            isLive: result.isLive,
            confidence: result.confidence,
            reason: result.reason
        });
    }
    catch (error) {
        res.status(500).json({ error: 'Liveness detection failed', message: error.message });
    }
});
/**
 * DELETE /biometric/facial
 * Remover biometria facial cadastrada (operação de alto risco)
 */
router.delete('/facial', authMiddleware.requireAuth, authMiddleware.requireStepUp, async (req, res) => {
    try {
        const userId = req.user?.userId;
        if (!userId)
            throw new Error('User ID not found');
        await facialService.removeBiometric(userId);
        // Auditoria crítica
        await auditService.log({
            userId,
            action: 'BIOMETRIC_FACIAL_REMOVED',
            entityType: 'user',
            entityId: userId,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
            severity: 'high',
        });
        res.json({ success: true, message: 'Facial biometric removed successfully' });
    }
    catch (error) {
        if (error.message === 'No facial biometric enrolled') {
            return res.status(404).json({ error: error.message });
        }
        res.status(500).json({ error: 'Failed to remove facial biometric', message: error.message });
    }
});
export { router as biometricRouter };
//# sourceMappingURL=biometric-facial.js.map
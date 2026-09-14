import { Router, Request, Response } from 'express';
import { RecoveryService } from '@zero/security';
import { AuthMiddleware } from '../middleware/auth.js';
import { AuditService } from '@zero/auth';

const router = Router();
const authMiddleware = new AuthMiddleware();
const recoveryService = new RecoveryService();
const auditService = new AuditService();

/**
 * POST /recovery/initiate
 * Iniciar processo de recuperação de conta
 */
router.post('/initiate', async (req: Request, res: Response) => {
  try {
    const { email, recoveryCode } = req.body;

    if (!email || !recoveryCode) {
      return res.status(400).json({ error: 'Email and recovery code required' });
    }

    // Validar recovery code e iniciar período de espera
    const result = await recoveryService.initiateRecovery(email, recoveryCode);

    // Auditoria
    await auditService.log({
      userId: result.userId,
      action: 'ACCOUNT_RECOVERY_INITIATED',
      entityType: 'user',
      entityId: result.userId,
      metadata: { 
        waitingPeriodHours: result.waitingPeriodHours,
        recoveryId: result.recoveryId 
      },
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      severity: 'high',
    });

    res.json({
      success: true,
      message: 'Recovery process initiated. Waiting period starts now.',
      data: {
        recoveryId: result.recoveryId,
        waitingPeriodHours: result.waitingPeriodHours,
        canCancelUntil: result.canCancelUntil,
      }
    });
  } catch (error: any) {
    if (error.message.includes('Invalid recovery code')) {
      return res.status(400).json({ error: error.message });
    }
    if (error.message.includes('No user found')) {
      return res.status(404).json({ error: error.message });
    }
    res.status(500).json({ error: 'Failed to initiate recovery', message: error.message });
  }
});

/**
 * GET /recovery/status/:recoveryId
 * Verificar status do processo de recuperação
 */
router.get('/status/:recoveryId', async (req: Request, res: Response) => {
  try {
    const { recoveryId } = req.params;

    const status = await recoveryService.getRecoveryStatus(recoveryId);

    res.json({
      success: true,
      data: status
    });
  } catch (error: any) {
    if (error.message === 'Recovery request not found') {
      return res.status(404).json({ error: error.message });
    }
    res.status(500).json({ error: 'Failed to get recovery status', message: error.message });
  }
});

/**
 * POST /recovery/cancel/:recoveryId
 * Cancelar processo de recuperação (se usuário não solicitou)
 */
router.post('/cancel/:recoveryId', async (req: Request, res: Response) => {
  try {
    const { recoveryId } = req.params;

    await recoveryService.cancelRecovery(recoveryId);

    // Auditoria crítica
    await auditService.log({
      action: 'ACCOUNT_RECOVERY_CANCELLED',
      entityType: 'recovery',
      entityId: recoveryId,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      severity: 'high',
    });

    res.json({
      success: true,
      message: 'Recovery process cancelled successfully'
    });
  } catch (error: any) {
    if (error.message === 'Recovery request not found') {
      return res.status(404).json({ error: error.message });
    }
    res.status(500).json({ error: 'Failed to cancel recovery', message: error.message });
  }
});

/**
 * POST /recovery/complete/:recoveryId
 * Completar recuperação após período de espera
 */
router.post('/complete/:recoveryId', async (req: Request, res: Response) => {
  try {
    const { recoveryId } = req.params;
    const { newPassword, newMfaSecret } = req.body;

    if (!newPassword) {
      return res.status(400).json({ error: 'New password required' });
    }

    const result = await recoveryService.completeRecovery(recoveryId, {
      newPassword,
      newMfaSecret,
    });

    // Auditoria crítica
    await auditService.log({
      userId: result.userId,
      action: 'ACCOUNT_RECOVERY_COMPLETED',
      entityType: 'user',
      entityId: result.userId,
      metadata: { 
        mfaReset: !!newMfaSecret,
        sessionsRevoked: result.sessionsRevoked 
      },
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      severity: 'critical',
    });

    res.json({
      success: true,
      message: 'Account recovery completed successfully',
      data: {
        userId: result.userId,
        sessionsRevoked: result.sessionsRevoked,
      }
    });
  } catch (error: any) {
    if (error.message === 'Recovery request not found') {
      return res.status(404).json({ error: error.message });
    }
    if (error.message === 'Waiting period not elapsed') {
      return res.status(400).json({ error: error.message });
    }
    res.status(500).json({ error: 'Failed to complete recovery', message: error.message });
  }
});

/**
 * POST /recovery/emergency-lockdown
 * Bloqueio de emergência da conta (usuário suspeita comprometimento)
 */
router.post('/emergency-lockdown', async (req: Request, res: Response) => {
  try {
    const { email, reason } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    const result = await recoveryService.emergencyLockdown(email, reason);

    // Auditoria crítica máxima
    await auditService.log({
      userId: result.userId,
      action: 'ACCOUNT_EMERGENCY_LOCKDOWN',
      entityType: 'user',
      entityId: result.userId,
      metadata: { reason },
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      severity: 'critical',
    });

    res.json({
      success: true,
      message: 'Account locked down successfully. Contact support for recovery.',
      data: {
        lockdownId: result.lockdownId,
        supportTicket: result.supportTicket,
      }
    });
  } catch (error: any) {
    if (error.message === 'User not found') {
      return res.status(404).json({ error: error.message });
    }
    res.status(500).json({ error: 'Failed to initiate emergency lockdown', message: error.message });
  }
});

export { router as recoveryRouter };

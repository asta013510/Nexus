import { Router } from 'express';
import { StorageService } from '@zero/storage';
import { AuthMiddleware } from '../middleware/auth.js';
import { AuditService } from '@zero/auth';
import { z } from 'zod';
const router = Router();
const authMiddleware = new AuthMiddleware();
const storageService = new StorageService();
const auditService = new AuditService();
// Schema de validação
const uploadSchema = z.object({
    name: z.string().min(1).max(255),
    categoryId: z.string().uuid().optional(),
    description: z.string().max(1000).optional(),
});
/**
 * POST /documents
 * Upload seguro de documento (criptografado client-side ou server-side)
 */
router.post('/', authMiddleware.requireAuth, async (req, res) => {
    try {
        const userId = req.user?.userId;
        if (!userId)
            throw new Error('User ID not found');
        // Validação básica (em produção, validar multipart/form-data rigorosamente)
        const validation = uploadSchema.safeParse(req.body);
        if (!validation.success) {
            return res.status(400).json({ error: 'Invalid input', details: validation.error });
        }
        const { name, categoryId, description } = validation.data;
        // Verificar se arquivo foi enviado
        if (!req.files || Array.isArray(req.files.file) || !req.files.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        const file = req.files.file;
        // Processar upload com criptografia e validação
        const document = await storageService.uploadDocument({
            userId,
            file: file.data,
            fileName: name,
            mimeType: file.mimetype,
            categoryId,
            description,
        });
        // Auditoria
        await auditService.log({
            userId,
            action: 'DOCUMENT_UPLOADED',
            entityType: 'document',
            entityId: document.id,
            metadata: { fileName: name, size: file.size },
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
        });
        res.status(201).json({ success: true, data: document });
    }
    catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to upload document', message: error.message });
    }
});
/**
 * GET /documents
 * Listar documentos do usuário
 */
router.get('/', authMiddleware.requireAuth, async (req, res) => {
    try {
        const userId = req.user?.userId;
        if (!userId)
            throw new Error('User ID not found');
        const { categoryId, search, page = '1', limit = '20' } = req.query;
        const documents = await storageService.listDocuments({
            userId,
            categoryId: categoryId,
            search: search,
            page: parseInt(page),
            limit: parseInt(limit),
        });
        res.json({ success: true, data: documents });
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to list documents', message: error.message });
    }
});
/**
 * GET /documents/:id
 * Obter metadados de um documento
 */
router.get('/:id', authMiddleware.requireAuth, async (req, res) => {
    try {
        const userId = req.user?.userId;
        if (!userId)
            throw new Error('User ID not found');
        const { id } = req.params;
        const document = await storageService.getDocumentById(id, userId);
        // Auditoria de visualização
        await auditService.log({
            userId,
            action: 'DOCUMENT_VIEWED',
            entityType: 'document',
            entityId: id,
            metadata: { fileName: document.name },
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
        });
        res.json({ success: true, data: document });
    }
    catch (error) {
        if (error.message === 'Document not found' || error.message === 'Access denied') {
            return res.status(404).json({ error: error.message });
        }
        res.status(500).json({ error: 'Failed to get document', message: error.message });
    }
});
/**
 * GET /documents/:id/download
 * Download seguro (descriptografa em tempo real)
 */
router.get('/:id/download', authMiddleware.requireAuth, async (req, res) => {
    try {
        const userId = req.user?.userId;
        if (!userId)
            throw new Error('User ID not found');
        const { id } = req.params;
        const { stream, metadata } = await storageService.downloadDocument(id, userId);
        // Headers seguros
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${metadata.name}"`);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        // Auditoria
        await auditService.log({
            userId,
            action: 'DOCUMENT_DOWNLOADED',
            entityType: 'document',
            entityId: id,
            metadata: { fileName: metadata.name },
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
        });
        stream.pipe(res);
    }
    catch (error) {
        if (error.message === 'Document not found' || error.message === 'Access denied') {
            return res.status(404).json({ error: error.message });
        }
        res.status(500).json({ error: 'Failed to download document', message: error.message });
    }
});
/**
 * DELETE /documents/:id
 * Exclusão segura (soft delete)
 */
router.delete('/:id', authMiddleware.requireAuth, async (req, res) => {
    try {
        const userId = req.user?.userId;
        if (!userId)
            throw new Error('User ID not found');
        const { id } = req.params;
        await storageService.deleteDocument(id, userId);
        // Auditoria
        await auditService.log({
            userId,
            action: 'DOCUMENT_DELETED',
            entityType: 'document',
            entityId: id,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
        });
        res.json({ success: true, message: 'Document marked for deletion' });
    }
    catch (error) {
        if (error.message === 'Document not found' || error.message === 'Access denied') {
            return res.status(404).json({ error: error.message });
        }
        res.status(500).json({ error: 'Failed to delete document', message: error.message });
    }
});
/**
 * POST /documents/:id/restore
 * Restaurar documento excluído
 */
router.post('/:id/restore', authMiddleware.requireAuth, async (req, res) => {
    try {
        const userId = req.user?.userId;
        if (!userId)
            throw new Error('User ID not found');
        const { id } = req.params;
        await storageService.restoreDocument(id, userId);
        // Auditoria
        await auditService.log({
            userId,
            action: 'DOCUMENT_RESTORED',
            entityType: 'document',
            entityId: id,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
        });
        res.json({ success: true, message: 'Document restored' });
    }
    catch (error) {
        if (error.message === 'Document not found' || error.message === 'Access denied') {
            return res.status(404).json({ error: error.message });
        }
        res.status(500).json({ error: 'Failed to restore document', message: error.message });
    }
});
export { router as documentsRouter };
//# sourceMappingURL=documents.js.map
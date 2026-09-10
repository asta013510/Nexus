"use strict";
/**
 * @zero/storage - Secure Document Storage Service
 *
 * Provides encrypted storage and retrieval of documents using S3-compatible storage.
 *
 * Security features:
 * - Server-side encryption with customer-managed keys (SSE-C)
 * - Presigned URLs with short expiration
 * - Content-type validation
 * - File size limits
 * - Malware scanning hooks (future)
 */
Object.defineProperty(exports, "__esModule", { value: true });
const client_s3_1 = require("@aws-sdk/client-s3");
const s3_request_presigner_1 = require("@aws-sdk/s3-request-presigner");
const crypto_1 = require("@zero/crypto");
const shared_1 = require("@zero/shared");
// Constants
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const PRESIGNED_URL_EXPIRY = 300; // 5 minutes
const ALLOWED_MIME_TYPES = new Set([
    'application/pdf',
    'image/jpeg',
    'image/png',
    'image/gif',
    'text/plain',
    'text/csv',
    'application/json',
    'application/zip',
    'application/x-zip-compressed',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
]);
const BLOCKED_EXTENSIONS = new Set([
    '.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js', '.jar',
    '.msi', '.dll', '.com', '.pif', '.scr', '.wsf', '.wsh',
]);
class StorageService {
    client;
    bucketName;
    useEncryption;
    constructor(config) {
        this.bucketName = config.bucketName;
        this.useEncryption = config.useEncryption;
        const s3Config = {
            region: config.region,
            credentials: {
                accessKeyId: config.accessKeyId,
                secretAccessKey: config.secretAccessKey,
            },
            forcePathStyle: !!config.endpoint,
        };
        if (config.endpoint) {
            s3Config.endpoint = config.endpoint;
        }
        this.client = new client_s3_1.S3Client(s3Config);
    }
    /**
     * Validate file before upload
     */
    validateFile(file, filename, mimeType) {
        // Check file size
        if (file.length > MAX_FILE_SIZE) {
            throw new shared_1.ValidationError(`File size exceeds maximum allowed (${MAX_FILE_SIZE} bytes)`);
        }
        // Check blocked extensions
        const ext = filename.toLowerCase().substring(filename.lastIndexOf('.'));
        if (BLOCKED_EXTENSIONS.has(ext)) {
            throw new shared_1.ValidationError(`File extension '${ext}' is not allowed for security reasons`);
        }
        // Validate MIME type
        if (!ALLOWED_MIME_TYPES.has(mimeType)) {
            throw new shared_1.ValidationError(`MIME type '${mimeType}' is not allowed`);
        }
        // Additional MIME type validation (prevent MIME confusion attacks)
        if (!this.validateMimeTypeConsistency(file, mimeType)) {
            throw new shared_1.ValidationError('File content does not match declared MIME type');
        }
    }
    /**
     * Basic MIME type consistency check
     * In production, integrate with a proper file inspection library
     */
    validateMimeTypeConsistency(file, declaredMimeType) {
        // Simple magic byte checks for common formats
        const magicBytes = {
            'application/pdf': [0x25, 0x50, 0x44, 0x46], // %PDF
            'image/jpeg': [0xFF, 0xD8, 0xFF],
            'image/png': [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            'image/gif': [0x47, 0x49, 0x46, 0x38], // GIF8
            'application/zip': [0x50, 0x4B, 0x03, 0x04], // PK..
            'application/x-zip-compressed': [0x50, 0x4B, 0x03, 0x04],
        };
        const expected = magicBytes[declaredMimeType];
        if (!expected) {
            return true; // No magic bytes defined for this type, allow it
        }
        return expected.every((byte, index) => file[index] === byte);
    }
    /**
     * Upload a file with encryption
     */
    async upload(userId, documentId, filename, file, mimeType) {
        // Validate file
        this.validateFile(file, filename, mimeType);
        // Generate encryption key for this file
        const encryptionKey = (0, crypto_1.randomBytes)(32);
        const encryptionKeyId = `key-${documentId}-${Date.now()}`;
        // Encrypt file content
        let encryptedContent = file;
        let iv;
        let authTag;
        if (this.useEncryption) {
            const encrypted = await (0, crypto_1.encryptFile)(file, encryptionKey);
            encryptedContent = encrypted.encryptedData;
            iv = encrypted.iv;
            authTag = encrypted.authTag;
        }
        // Generate S3 key
        const key = `users/${userId}/documents/${documentId}/${filename}`;
        // Calculate hash of original file
        const hash = await this.calculateHash(file);
        // Upload to S3
        const command = new client_s3_1.PutObjectCommand({
            Bucket: this.bucketName,
            Key: key,
            Body: encryptedContent,
            ContentType: mimeType,
            Metadata: {
                'document-id': documentId,
                'user-id': userId,
                'original-filename': filename,
                'file-hash': hash,
                'encryption-key-id': encryptionKeyId,
                'encrypted': this.useEncryption.toString(),
                ...(iv && { 'encryption-iv': iv.toString('base64') }),
                ...(authTag && { 'encryption-auth-tag': authTag.toString('base64') }),
            },
        });
        await this.client.send(command);
        return {
            documentId,
            key,
            encryptionKeyId,
            size: file.length,
            hash,
            mimeType,
            uploadedAt: new Date(),
            ...(iv && { iv: iv.toString('base64') }),
            ...(authTag && { authTag: authTag.toString('base64') }),
        };
    }
    /**
     * Download and decrypt a file
     */
    async download(userId, documentId, encryptionKey, iv, authTag) {
        const key = `users/${userId}/documents/${documentId}`;
        const command = new client_s3_1.GetObjectCommand({
            Bucket: this.bucketName,
            Key: key,
        });
        const response = await this.client.send(command);
        if (!response.Body) {
            throw new shared_1.SecurityError('Empty response from storage');
        }
        const encryptedContent = await this.streamToBuffer(response.Body);
        // Decrypt if we have encryption metadata
        let content = encryptedContent;
        if (iv && authTag) {
            content = await (0, crypto_1.decryptFile)(encryptedContent, iv, authTag, encryptionKey);
        }
        return {
            stream: content,
            mimeType: response.ContentType || 'application/octet-stream',
            size: content.length,
            hash: response.Metadata?.['file-hash'] || '',
        };
    }
    /**
     * Generate presigned URL for secure temporary access
     */
    async generatePresignedUrl(userId, documentId, operation = 'get', expirySeconds = PRESIGNED_URL_EXPIRY) {
        const key = `users/${userId}/documents/${documentId}`;
        const command = operation === 'get'
            ? new client_s3_1.GetObjectCommand({ Bucket: this.bucketName, Key: key })
            : new client_s3_1.PutObjectCommand({ Bucket: this.bucketName, Key: key });
        const url = await (0, s3_request_presigner_1.getSignedUrl)(this.client, command, {
            expiresIn: expirySeconds,
        });
        return url;
    }
    /**
     * Delete a file securely
     */
    async delete(userId, documentId) {
        const key = `users/${userId}/documents/${documentId}`;
        const command = new client_s3_1.DeleteObjectCommand({
            Bucket: this.bucketName,
            Key: key,
        });
        await this.client.send(command);
    }
    /**
     * List documents for a user
     */
    async listDocuments(userId, prefix) {
        const basePrefix = `users/${userId}/documents/`;
        const fullPrefix = prefix ? `${basePrefix}${prefix}` : basePrefix;
        const command = new client_s3_1.ListObjectsV2Command({
            Bucket: this.bucketName,
            Prefix: fullPrefix,
            Delimiter: '/',
        });
        const response = await this.client.send(command);
        return (response.Contents || []).map(obj => obj.Key || '').filter(Boolean);
    }
    /**
     * Verify file integrity
     */
    async verifyIntegrity(userId, documentId, expectedHash) {
        try {
            const key = `users/${userId}/documents/${documentId}`;
            const command = new client_s3_1.HeadObjectCommand({
                Bucket: this.bucketName,
                Key: key,
            });
            const response = await this.client.send(command);
            const storedHash = response.Metadata?.['file-hash'];
            return storedHash === expectedHash;
        }
        catch {
            return false;
        }
    }
    /**
     * Helper: Calculate SHA-256 hash
     */
    async calculateHash(data) {
        const crypto = await import('crypto');
        return crypto.createHash('sha256').update(data).digest('hex');
    }
    /**
     * Helper: Convert stream to buffer
     */
    async streamToBuffer(stream) {
        const chunks = [];
        if (stream instanceof Buffer) {
            return stream;
        }
        return new Promise((resolve, reject) => {
            stream.on('data', (chunk) => chunks.push(chunk));
            stream.on('end', () => resolve(Buffer.concat(chunks)));
            stream.on('error', reject);
        });
    }
}
exports.default = StorageService;
//# sourceMappingURL=index.js.map
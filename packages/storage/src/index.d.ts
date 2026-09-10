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
export interface StorageConfig {
    endpoint?: string;
    region: string;
    accessKeyId: string;
    secretAccessKey: string;
    bucketName: string;
    useEncryption: boolean;
}
export interface UploadResult {
    documentId: string;
    key: string;
    encryptionKeyId: string;
    size: number;
    hash: string;
    mimeType: string;
    uploadedAt: Date;
    iv?: string;
    authTag?: string;
}
export interface DownloadResult {
    stream: Buffer;
    mimeType: string;
    size: number;
    hash: string;
}
export interface DocumentMetadata {
    id: string;
    userId: string;
    name: string;
    mimeType: string;
    size: number;
    hash: string;
    encryptionKeyId: string;
    version: number;
    createdAt: Date;
    updatedAt: Date;
}
declare class StorageService {
    private client;
    private bucketName;
    private useEncryption;
    constructor(config: StorageConfig);
    /**
     * Validate file before upload
     */
    private validateFile;
    /**
     * Basic MIME type consistency check
     * In production, integrate with a proper file inspection library
     */
    private validateMimeTypeConsistency;
    /**
     * Upload a file with encryption
     */
    upload(userId: string, documentId: string, filename: string, file: Buffer, mimeType: string): Promise<UploadResult>;
    /**
     * Download and decrypt a file
     */
    download(userId: string, documentId: string, encryptionKey: Buffer, iv: Buffer, authTag: Buffer): Promise<DownloadResult>;
    /**
     * Generate presigned URL for secure temporary access
     */
    generatePresignedUrl(userId: string, documentId: string, operation?: 'get' | 'put', expirySeconds?: number): Promise<string>;
    /**
     * Delete a file securely
     */
    delete(userId: string, documentId: string): Promise<void>;
    /**
     * List documents for a user
     */
    listDocuments(userId: string, prefix?: string): Promise<string[]>;
    /**
     * Verify file integrity
     */
    verifyIntegrity(userId: string, documentId: string, expectedHash: string): Promise<boolean>;
    /**
     * Helper: Calculate SHA-256 hash
     */
    private calculateHash;
    /**
     * Helper: Convert stream to buffer
     */
    private streamToBuffer;
}
export default StorageService;
//# sourceMappingURL=index.d.ts.map
/**
 * Tipos globais para Crypto API do Node.js
 */
interface CryptoKey {
    readonly algorithm: KeyAlgorithm;
    readonly extractable: boolean;
    readonly type: string;
    readonly usages: string[];
}
interface KeyAlgorithm {
    name: string;
    length?: number;
    hash?: {
        name: string;
    };
    iv?: BufferSource;
    salt?: BufferSource;
    iterations?: number;
}
interface PublicKeyCredential extends EventTarget {
    readonly type: string;
    readonly id: string;
    readonly rawId: ArrayBuffer;
    readonly authenticatorAttachment: string | null;
    getClientExtensionResults(): Record<string, unknown>;
}
declare global {
    interface Window {
        CryptoKey: typeof CryptoKey;
        PublicKeyCredential: typeof PublicKeyCredential;
    }
}
export type { CryptoKey, PublicKeyCredential, KeyAlgorithm };
//# sourceMappingURL=types.d.ts.map
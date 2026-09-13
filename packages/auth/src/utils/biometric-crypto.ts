/**
 * ZERO - Utilitários de Criptografia para Biometria
 * 
 * Funções para transformação irreversível de templates biométricos.
 */

import { randomBytes } from 'crypto';

/**
 * Gera um salt criptograficamente seguro.
 */
export async function generateSalt(): Promise<string> {
  return randomBytes(32).toString('hex');
}

/**
 * Aplica transformação irreversível ao template biométrico.
 * Combina embeddings com salt e aplica hash criptográfico.
 */
export async function hashTemplate(template: {
  embeddings: Float32Array;
  salt: string;
}): Promise<string> {
  const encoder = new TextEncoder();
  
  // Converte embeddings para array normal
  const embeddingsArray = Array.from(template.embeddings);
  
  // Combina embeddings + salt
  const data = JSON.stringify({
    embeddings: embeddingsArray,
    salt: template.salt
  });
  
  // Hash SHA-256
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return hashHex;
}

/**
 * Compara dois templates de forma segura (constant-time).
 */
export async function compareTemplates(
  template1: string,
  template2: string
): Promise<boolean> {
  if (template1.length !== template2.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < template1.length; i++) {
    diff |= template1.charCodeAt(i) ^ template2.charCodeAt(i);
  }

  return diff === 0;
}

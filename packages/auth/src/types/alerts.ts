/**
 * Tipos de alerta de segurança
 */
export type AlertType =
  | 'security'           // Ameaça de segurança direta
  | 'anomalous_activity' // Comportamento anômalo detectado
  | 'account_change'     // Alteração na conta
  | 'device'             // Evento de dispositivo
  | 'session'            // Evento de sessão
  | 'document'           // Evento relacionado a documentos
  | 'system';            // Evento do sistema

/**
 * Prioridade do alerta
 */
export type AlertPriority = 'critical' | 'high' | 'medium' | 'low';

/**
 * Status do alerta
 */
export type AlertStatus =
  | 'pending'      // Não lido
  | 'acknowledged' // Usuário viu
  | 'resolved';    // Problema tratado

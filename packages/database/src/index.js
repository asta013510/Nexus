"use strict";
/**
 * @zero/database - Módulo de Banco de Dados
 *
 * PostgreSQL + Drizzle ORM
 * Conexão segura com pool e Row-Level Security
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.schema = void 0;
exports.createDatabaseClient = createDatabaseClient;
var schema_1 = require("./schema");
Object.defineProperty(exports, "schema", { enumerable: true, get: function () { return schema_1.schema; } });
__exportStar(require("./schema"), exports);
// Database connection helper (será implementado na API)
function createDatabaseClient(connectionString) {
    // Implementação será feita no pacote da API
    throw new Error('Database client deve ser inicializado pela API');
}
//# sourceMappingURL=index.js.map
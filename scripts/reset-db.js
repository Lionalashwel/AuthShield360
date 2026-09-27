/**
 * AuthShield 360 - DB reset CLI
 *   node scripts/reset-db.js   -> wipe + reseed (fictional seed accounts)
 */
import { initDb } from '../backend/db.js';
import { DB_PATH } from '../backend/config.js';

initDb(true);
console.log('[db] reset complete ->', DB_PATH);
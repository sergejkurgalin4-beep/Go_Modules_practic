import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Все настройки берутся из переменных окружения (см. .env.example).
export function loadConfig(env = process.env) {
  return {
    host: env.HOST || '127.0.0.1',
    port: Number(env.PORT) || 3000,
    dbPath: env.DB_PATH || path.join(ROOT, 'data', 'gochs.db'),
    publicDir: path.join(ROOT, 'public'),
    production: env.NODE_ENV === 'production',
    // За обратным прокси (nginx и т. п.) укажите TRUST_PROXY=1, чтобы видеть реальный IP клиента.
    trustProxy: env.TRUST_PROXY ? Number(env.TRUST_PROXY) || env.TRUST_PROXY : false,
    sessionTtlMs: (Number(env.SESSION_TTL_HOURS) || 8) * 60 * 60 * 1000,
    loginRateLimit: { windowMs: 15 * 60 * 1000, max: Number(env.LOGIN_RATE_MAX) || 30 }
  };
}

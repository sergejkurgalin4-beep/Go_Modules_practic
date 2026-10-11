import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
const PARAMS = { N: 16384, r: 8, p: 1 };
const KEY_LENGTH = 64;
const MAXMEM = 64 * 1024 * 1024;

export async function hashSecret(secret) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(secret, salt, KEY_LENGTH, { ...PARAMS, maxmem: MAXMEM });
  return ['scrypt', PARAMS.N, PARAMS.r, PARAMS.p, salt.toString('base64'), key.toString('base64')].join('$');
}

export async function verifySecret(secret, stored) {
  const [algorithm, N, r, p, saltB64, keyB64] = String(stored).split('$');
  if (algorithm !== 'scrypt') return false;
  const expected = Buffer.from(keyB64, 'base64');
  const key = await scrypt(secret, Buffer.from(saltB64, 'base64'), expected.length, {
    N: Number(N), r: Number(r), p: Number(p), maxmem: MAXMEM
  });
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}

export const DUMMY_HASH = await hashSecret(crypto.randomBytes(8).toString('hex'));

export function newSessionToken() {
  const token = crypto.randomBytes(32).toString('base64url');
  return { token, id: sha256(token) };
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function rateLimit({ windowMs, max }) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip;
    const entry = hits.get(key);
    if (!entry || entry.resetAt <= now) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    entry.count += 1;
    if (entry.count > max) {
      res.set('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));
      return res.status(429).json({ error: 'Слишком много попыток входа. Повторите позже.' });
    }
    next();
  };
}

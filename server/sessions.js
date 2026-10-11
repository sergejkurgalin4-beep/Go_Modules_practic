import { newSessionToken, sha256 } from './security.js';

export const COOKIE_NAME = 'sid';


export function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0 && part.slice(0, index).trim() === name) {
      return decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return null;
}

export function setSessionCookie(res, token, config) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.production,
    path: '/',
    maxAge: config.sessionTtlMs
  });
}

export function clearSessionCookie(res, config) {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'lax', secure: config.production, path: '/' });
}


export function audit(db, { userId = null, event, method = null, identifier = null, ctx = {}, details = null }) {
  db.prepare(`INSERT INTO audit_log (user_id, event, method, identifier, ip, user_agent, details, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(userId, event, method, identifier && String(identifier).slice(0, 100),
         ctx.ip ?? null, ctx.userAgent ?? null, details, Date.now());
}


export function createSession(db, config, { userId, method, ctx }) {
  const { token, id } = newSessionToken();
  const now = Date.now();
  db.prepare(`INSERT INTO sessions (id, user_id, method, ip, user_agent, created_at, last_seen_at, expires_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, userId, method, ctx.ip ?? null, ctx.userAgent ?? null, now, now, now + config.sessionTtlMs);
  return { token, id };
}

export function findSession(db, token) {
  if (!token) return null;
  const id = sha256(token);
  const row = db.prepare('SELECT * FROM sessions WHERE id = ?').get(id);
  if (!row || row.ended_at) return null;

  const now = Date.now();
  if (row.expires_at <= now) {
    endSession(db, id, 'timeout', row.expires_at);
    audit(db, { userId: row.user_id, event: 'session_expired', method: row.method });
    return null;
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1').get(row.user_id);
  if (!user) return null;

  db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(now, id);
  return { sessionId: id, user, method: row.method };
}

export function endSession(db, sessionId, reason, at = Date.now()) {
  db.prepare('UPDATE sessions SET ended_at = ?, end_reason = ? WHERE id = ? AND ended_at IS NULL')
    .run(at, reason, sessionId);
}

export function endAllSessions(db, userId, reason) {
  return db.prepare('UPDATE sessions SET ended_at = ?, end_reason = ? WHERE user_id = ? AND ended_at IS NULL')
    .run(Date.now(), reason, userId).changes;
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.auth.user.role)) return res.status(403).json({ error: 'Недостаточно прав.' });
    next();
  };
}

export function requireAuth(db) {
  return (req, res, next) => {
    const auth = findSession(db, readCookie(req, COOKIE_NAME));
    if (!auth) return res.status(401).json({ error: 'Требуется вход в систему.' });
    req.auth = auth;
    next();
  };
}

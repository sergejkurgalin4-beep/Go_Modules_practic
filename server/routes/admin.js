import { Router } from 'express';
import { audit, endAllSessions, requireAuth, requireRole } from '../sessions.js';
import { CRITICAL_EVENTS, describeEvent } from '../audit-events.js';

const DAY_MS = 24 * 60 * 60 * 1000;

function context(req) {
  return { ip: req.ip, userAgent: (req.get('user-agent') || '').slice(0, 300) };
}

export function adminRouter({ db }) {
  const router = Router();
  router.use(requireAuth(db), requireRole('admin'));

  router.get('/users', (req, res) => {
    const now = Date.now();
    const rows = db.prepare(`
      SELECT u.id, u.login, u.full_name, u.position, u.role, u.personnel_number, u.department,
             u.locked_until, t.model AS token_model, t.locked AS token_locked,
             c.serial_number AS cert_serial, c.valid_to AS cert_valid_to,
             (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.ended_at IS NULL AND s.expires_at > @now) AS active_sessions,
             (SELECT created_at FROM sessions s WHERE s.user_id = u.id ORDER BY created_at DESC LIMIT 1) AS last_login_at,
             (SELECT ip FROM sessions s WHERE s.user_id = u.id ORDER BY created_at DESC LIMIT 1) AS last_login_ip
      FROM users u
      LEFT JOIN tokens t ON t.user_id = u.id
      LEFT JOIN certificates c ON c.id = (SELECT id FROM certificates WHERE user_id = u.id ORDER BY valid_to DESC LIMIT 1)
      WHERE u.is_active = 1
      ORDER BY u.full_name`).all({ now });

    const users = rows.map(row => ({
      id: row.id,
      login: row.login,
      fullName: row.full_name,
      position: row.position,
      department: row.department,
      personnelNumber: row.personnel_number,
      role: row.role,
      tokenModel: row.token_model,
      certificate: row.cert_serial ? { serialNumber: row.cert_serial, validTo: row.cert_valid_to } : null,
      lastLogin: row.last_login_at ? { at: row.last_login_at, ip: row.last_login_ip } : null,
      activeSessions: row.active_sessions,
      locked: Boolean((row.locked_until && row.locked_until > now) || row.token_locked)
    }));

    res.json({
      total: users.length,
      roles: new Set(users.map(user => user.role)).size,
      activeSessions: users.reduce((sum, user) => sum + user.activeSessions, 0),
      users
    });
  });

  router.get('/audit', (req, res) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const q = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 100) : '';
    const criticalOnly = req.query.critical === '1';

    const where = [];
    const params = {};
    if (q) {
      where.push(`(a.ip LIKE @like ESCAPE '\\' OR a.event LIKE @like ESCAPE '\\' OR a.identifier LIKE @like ESCAPE '\\' OR u.login LIKE @like ESCAPE '\\' OR u.full_name LIKE @like ESCAPE '\\')`);
      params.like = `%${q.replace(/[%_\\]/g, '\\$&')}%`;
    }
    if (criticalOnly) {
      where.push(`a.event IN (${CRITICAL_EVENTS.map((_, i) => `@c${i}`).join(', ')})`);
      CRITICAL_EVENTS.forEach((event, i) => { params[`c${i}`] = event; });
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const fromJoin = `FROM audit_log a LEFT JOIN users u ON u.id = a.user_id ${clause}`;

    const items = db.prepare(`
      SELECT a.id, a.event, a.method, a.identifier, a.ip, a.user_agent, a.details, a.created_at,
             u.login, u.full_name ${fromJoin} ORDER BY a.created_at DESC, a.id DESC LIMIT @limit OFFSET @offset`)
      .all({ ...params, limit, offset })
      .map(row => ({
        id: row.id,
        at: row.created_at,
        event: row.event,
        ...describeEvent(row.event),
        method: row.method,
        identifier: row.identifier,
        ip: row.ip,
        userAgent: row.user_agent,
        details: row.details,
        user: row.login ? { login: row.login, fullName: row.full_name } : null
      }));

    const matching = db.prepare(`SELECT COUNT(*) AS n ${fromJoin}`).get(params).n;
    const since = Date.now() - DAY_MS;
    const critical = CRITICAL_EVENTS.map(() => '?').join(', ');
    const last24h = db.prepare('SELECT COUNT(*) AS n FROM audit_log WHERE created_at >= ?').get(since).n;
    const critical24h = db.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE created_at >= ? AND event IN (${critical})`)
      .get(since, ...CRITICAL_EVENTS).n;
    const lastCritical = db.prepare(`SELECT MAX(created_at) AS at FROM audit_log WHERE event IN (${critical})`)
      .get(...CRITICAL_EVENTS).at;

    res.json({
      total: db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n,
      matching, last24h, critical24h, lastCriticalAt: lastCritical, items
    });
  });

  router.post('/users/:id/reset-sessions', (req, res) => {
    const id = Number(req.params.id);
    const target = Number.isInteger(id) ? db.prepare('SELECT id, login FROM users WHERE id = ?').get(id) : null;
    if (!target) return res.status(404).json({ error: 'Пользователь не найден.' });

    const closed = endAllSessions(db, target.id, 'forced');
    audit(db, { userId: req.auth.user.id, event: 'admin_session_reset', method: req.auth.method,
                ctx: context(req), details: `target:${target.login};closed:${closed}` });
    res.json({ closed });
  });

  return router;
}

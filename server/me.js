const ROLE_LABELS = {
  head: 'Руководитель / зам. по ГОЧС',
  hq: 'Ответственный за ГО (Начальник штаба ГОЧС)',
  commander: 'Командир звена',
  admin: 'Администратор безопасности ГОЧС (SU / ROOT)'
};

const DAY_MS = 24 * 60 * 60 * 1000;

function formatSnils(digits) {
  if (!digits) return null;
  return `${digits.slice(0, 3)}-${digits.slice(3, 6)}-${digits.slice(6, 9)} ${digits.slice(9)}`;
}

function initialsOf(fullName) {
  const [surname = '', name = ''] = fullName.split(' ');
  return (surname[0] ?? '') + (name[0] ?? '');
}

function sessionStatus(row, now) {
  if (!row.ended_at && row.expires_at > now) return 'active';
  return row.end_reason ?? 'timeout';
}

export function buildMe(db, user, currentSessionId) {
  const now = Date.now();

  const token = db.prepare('SELECT * FROM tokens WHERE user_id = ?').get(user.id);
  const cert = db.prepare('SELECT * FROM certificates WHERE user_id = ? ORDER BY valid_to DESC LIMIT 1').get(user.id);
  const delegations = db.prepare('SELECT title FROM delegations WHERE user_id = ? ORDER BY position, id')
    .all(user.id).map(row => row.title);

  const total = db.prepare('SELECT COUNT(*) AS n FROM audit_log WHERE user_id = ?').get(user.id).n;
  const sessions = db.prepare('SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10')
    .all(user.id)
    .map(row => ({
      startedAt: row.created_at,
      ip: row.ip,
      method: row.method,
      status: sessionStatus(row, now),
      current: row.id === currentSessionId
    }));

  return {
    user: {
      login: user.login,
      fullName: user.full_name,
      shortName: user.short_name,
      initials: initialsOf(user.full_name),
      position: user.position,
      shortPosition: user.short_position,
      role: user.role,
      roleLabel: ROLE_LABELS[user.role],
      employeeCode: user.employee_code,
      snils: formatSnils(user.snils_digits),
      personnelNumber: user.personnel_number,
      phone: user.phone,
      email: user.email,
      department: user.department,
      appointmentOrder: user.appointment_order,
      clearance: user.clearance,
      workstation: user.workstation
    },
    token: token ? { serial: token.serial, model: token.model, attemptsLeft: token.pin_attempts_left, locked: !!token.locked } : null,
    certificate: cert ? {
      serialNumber: cert.serial_number,
      issuer: cert.issuer,
      thumbprint: cert.thumbprint,
      validFrom: cert.valid_from,
      validTo: cert.valid_to,
      status: cert.status,
      daysLeft: Math.max(0, Math.ceil((cert.valid_to - now) / DAY_MS))
    } : null,
    delegations,
    audit: { total, sessions }
  };
}

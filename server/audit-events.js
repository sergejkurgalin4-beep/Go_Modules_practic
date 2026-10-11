// Каталог событий журнала безопасности: уровень и «код события» (EID) для интерфейса администратора.
// Критическими (ALERT) считаются события, которые требуют реакции службы безопасности.
export const AUDIT_EVENTS = {
  login_ok: { level: 'AUDIT_OK', eid: 1102, category: 'Аутентификация', title: 'Успешная аутентификация' },
  login_fail: { level: 'WARNING', eid: 4104, category: 'Аутентификация', title: 'Неудачная попытка аутентификации' },
  login_denied: { level: 'WARNING', eid: 4105, category: 'Контроль доступа', title: 'Отказ в доступе: роль или сертификат не соответствуют' },
  lockout: { level: 'ALERT', eid: 7001, category: 'Защита от подбора', title: 'Блокировка учётной записи после серии неудачных попыток' },
  token_locked: { level: 'ALERT', eid: 7002, category: 'Защита от подбора', title: 'Блокировка ключевого носителя КЭП (неверный PIN)' },
  logout: { level: 'INFO', eid: 2201, category: 'Сеансы', title: 'Завершение сеанса пользователем' },
  logout_all: { level: 'WARNING', eid: 4106, category: 'Сеансы', title: 'Принудительное завершение всех сеансов пользователя' },
  session_expired: { level: 'INFO', eid: 2202, category: 'Сеансы', title: 'Сеанс завершён по таймауту' },
  admin_session_reset: { level: 'WARNING', eid: 4107, category: 'Администрирование', title: 'Сброс сеансов пользователя администратором' }
};

export const CRITICAL_EVENTS = Object.entries(AUDIT_EVENTS)
  .filter(([, info]) => info.level === 'ALERT')
  .map(([event]) => event);

export const describeEvent = event =>
  AUDIT_EVENTS[event] ?? { level: 'INFO', eid: 0, category: 'Прочее', title: event };

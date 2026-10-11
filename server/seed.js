import './check-node.js';
import { pathToFileURL } from 'node:url';
import fs from 'node:fs';
import { loadConfig } from './config.js';
import { openDb } from './db.js';
import { hashSecret } from './security.js';

const DAY = 24 * 60 * 60 * 1000;

export const DEMO_USERS = [
  {
    login: 'voronov', password: 'Voronov#2026', snils: '14829381094', role: 'head',
    fullName: 'Воронов Сергей Михайлович', shortName: 'С. М. Воронов',
    position: 'Заместитель генерального директора по промышленной безопасности, охране труда и ГОЧС',
    shortPosition: 'Зам. ген. директора по ГОЧС',
    employeeCode: 'EMP-00CHS-00418', personnelNumber: 'ТН-000412-НХП',
    phone: '+7 (495) 829-10-08 (доб. 41-82)', email: 'voronov_sm@sec.neftekhimprom.ru',
    department: 'Дирекция по комплексной безопасности, гражданской обороне и чрезвычайным ситуациям',
    appointmentOrder: 'Приказ Генерального директора ПАО «Нефтехимпром» № 118-к/ОД от 14.02.2021 г.',
    clearance: 'Сов. Секретно (Форма № 2)', workstation: 'WS-SEC-042 (Сертифицированный контур)',
    delegations: [
      'Оперативные донесения (Форма 1/ЧС, 2-ДУ)',
      'План действий по предупреждению и ликвидации ЧС',
      'Донесения в ГУ МЧС России по субъекту РФ',
      'Акты списания и закладки средств СИЗ и МТС'
    ],
    token: { serial: '38291048-A', model: 'Рутокен ЭЦП 3.0 NFC', pin: '12345678' },
    certificate: {
      serialNumber: '0009 4F02 B710 4A38 901E 521C 8B20 9B13',
      issuer: 'АО «Аналитический Центр» – Минцифры России (ГОСТ-Р ИК-9)',
      thumbprint: '7B42 A991 3C8F 1120 4493 DC00 F890 0184 EC41 7D92'
    }
  },
  {
    login: 'kuznetsov', password: 'Kuznetsov#2026', snils: '11223344595', role: 'hq',
    fullName: 'Кузнецов Андрей Петрович', shortName: 'А. П. Кузнецов',
    position: 'Начальник штаба гражданской обороны и чрезвычайных ситуаций',
    shortPosition: 'Начальник штаба ГОЧС',
    employeeCode: 'EMP-00CHS-00102', department: 'Штаб ГОЧС предприятия', workstation: 'WS-SEC-017 (Сертифицированный контур)'
  },
  {
    login: 'komissarov', password: 'Komissarov#2026', snils: '17713948532', role: 'admin',
    fullName: 'Комиссаров Валерий Дмитриевич', shortName: 'Комиссаров В. Д.',
    position: 'Администратор безопасности ГОЧС (SU / ROOT), главный специалист по ИБ',
    shortPosition: 'Администратор безопасности ГОЧС',
    employeeCode: 'EMP-00CHS-00194', personnelNumber: '00194', department: 'Служба безопасности ГОЧС',
    workstation: 'WS-SEC-001 (Сертифицированный контур)'
  },
  {
    login: 'ilyin', password: 'Ilyin#2026', snils: '12345678964', role: 'commander',
    fullName: 'Ильин Роман Константинович', shortName: 'Ильин Р. К.',
    position: 'Командир звена, мастер участка №3', shortPosition: 'Командир звена, мастер участка №3',
    employeeCode: 'EMP-00CHS-00733', department: 'Цех №3'
  }
];

export async function seedDemo(db) {
  const exists = db.prepare('SELECT 1 FROM users WHERE login = ?');
  const insertUser = db.prepare(`
    INSERT INTO users (login, snils_digits, password_hash, full_name, short_name, position, short_position, role,
                       employee_code, personnel_number, phone, email, department, appointment_order, clearance, workstation)
    VALUES (@login, @snils, @hash, @fullName, @shortName, @position, @shortPosition, @role,
            @employeeCode, @personnelNumber, @phone, @email, @department, @appointmentOrder, @clearance, @workstation)`);
  const insertToken = db.prepare('INSERT INTO tokens (serial, model, user_id, pin_hash) VALUES (?, ?, ?, ?)');
  const insertCert = db.prepare(`INSERT INTO certificates (user_id, token_id, serial_number, issuer, thumbprint, valid_from, valid_to)
                                 VALUES (?, ?, ?, ?, ?, ?, ?)`);
  const insertDelegation = db.prepare('INSERT INTO delegations (user_id, title, position) VALUES (?, ?, ?)');

  let created = 0;
  for (const u of DEMO_USERS) {
    if (exists.get(u.login)) continue;
    const hash = await hashSecret(u.password);
    const pinHash = u.token ? await hashSecret(u.token.pin) : null;

    db.transaction(() => {
      const fields = ['login', 'snils', 'role', 'fullName', 'shortName', 'position', 'shortPosition', 'employeeCode',
                      'personnelNumber', 'phone', 'email', 'department', 'appointmentOrder', 'clearance', 'workstation'];
      const params = Object.fromEntries(fields.map(key => [key, u[key] ?? null]));
      const userId = insertUser.run({ ...params, hash }).lastInsertRowid;

      let tokenId = null;
      if (u.token) tokenId = insertToken.run(u.token.serial, u.token.model, userId, pinHash).lastInsertRowid;
      if (u.certificate) {
        const validTo = Date.now() + 180 * DAY;
        insertCert.run(userId, tokenId, u.certificate.serialNumber, u.certificate.issuer,
                       u.certificate.thumbprint, validTo - 730 * DAY, validTo);
      }
      (u.delegations ?? []).forEach((title, i) => insertDelegation.run(userId, title, i));
    })();
    created += 1;
  }
  return created;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const config = loadConfig();
  if (process.argv.includes('--reset') && config.dbPath !== ':memory:') {
    for (const suffix of ['', '-wal', '-shm']) fs.rmSync(config.dbPath + suffix, { force: true });
    console.log('База очищена.');
  }
  const db = openDb(config.dbPath);
  const created = await seedDemo(db);
  console.log(created ? `Создано демо-пользователей: ${created}` : 'Демо-пользователи уже существуют.');
  console.log('\nДемо-доступ (только для локального запуска):');
  for (const u of DEMO_USERS) console.log(`  ${u.role.padEnd(9)} логин: ${u.login.padEnd(10)} пароль: ${u.password}`);
  console.log('  КЭП: носитель 38291048-A, PIN 12345678 (пользователь voronov)');
  db.close();
}

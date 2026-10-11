"use strict";

const landingApp = document.getElementById("landingApp");
const adminApp = document.getElementById("adminApp");
const commanderApp = document.getElementById("commanderApp");
const gaApp = document.getElementById("gochsAdminApp");
const authDialog = document.getElementById("authDialog");
const breadcrumbSection = document.getElementById("breadcrumbSection");
const breadcrumbTitle = document.getElementById("breadcrumbTitle");

const adminViews = document.querySelectorAll(".admin-view");
const gaViews = document.querySelectorAll(".ga-view");
const gaButtons = document.querySelectorAll("[data-ga-tab]");
const adminButtons = document.querySelectorAll("[data-admin-tab]");
const scrollButtons = document.querySelectorAll("[data-scroll]");
const authTabs = document.querySelectorAll("[data-auth-tab]");
const authPanels = document.querySelectorAll("[data-auth-panel]");
const landingNavLinks = document.querySelectorAll(".land-nav [data-jump]");

const DEFAULT_TAB = "documents";
const DEFAULT_SECTION = "Нормативно-правовой контур";
const DEFAULT_GA_TAB = "monitoring";
const GA_TABS = ["monitoring", "formations", "shelters", "ppe", "training", "reports", "documents", "rbac", "audit"];

const tabTitles = {
  monitoring: "Сводный мониторинг",
  formations: "Формирования (НФГО / НАСФ)",
  shelters: "Защитные сооружения (ЗС ГО)",
  ppe: "Обеспеченность СИЗ и МТС",
  training: "Обучение и учения",
  reports: "Отчётность в МЧС России",
  documents: "Регламенты и документация",
  profile: "Карточка должностного лица ГОЧС"
};

const tabSections = {
  profile: "Штабной состав и ответственные лица"
};

const ROLE_SCREEN = { head: "admin", hq: "admin", commander: "commander", admin: "ga" };

class ApiError extends Error {
  constructor(status, message, data = null) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

async function api(path, { method = "GET", body } = {}) {
  let response;
  try {
    response = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined
    });
  } catch {
    throw new ApiError(
      0,
      "Сервер недоступен. Запустите его командой «npm start» и откройте адрес http://localhost:3000."
    );
  }

  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError(response.status, data?.error ?? "Ошибка запроса.", data);
  }
  return data;
}

let me = null;

function lookup(object, path) {
  return path.split(".").reduce((value, key) => value?.[key], object);
}

const dateParts = new Intl.DateTimeFormat("ru-RU", {
  timeZone: "Europe/Moscow",
  day: "2-digit", month: "2-digit", year: "numeric",
  hour: "2-digit", minute: "2-digit", second: "2-digit",
  hour12: false
});

function moscowParts(timestamp) {
  return Object.fromEntries(dateParts.formatToParts(timestamp).map(part => [part.type, part.value]));
}

const formatDate = timestamp => {
  const p = moscowParts(timestamp);
  return `${p.day}.${p.month}.${p.year}`;
};

function bindData() {
  document.querySelectorAll("[data-bind]").forEach(element => {
    const scope = element.closest("[data-only-role]");
    if (scope && scope.dataset.onlyRole !== me.user.role) return;

    let value = lookup(me, element.dataset.bind);
    if (value === null || value === undefined || value === "") {
      value = "—";
    } else {
      if (element.dataset.format === "date") value = formatDate(value);
      if (element.dataset.template) value = element.dataset.template.replace("{}", value);
    }
    element.textContent = value;
  });

  document.querySelectorAll("[data-requires]").forEach(element => {
    element.hidden = !lookup(me, element.dataset.requires);
  });

  renderDelegations();
  renderAudit();
}

function createElement(tag, { className, text, attrs } = {}, ...children) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  if (attrs) Object.entries(attrs).forEach(([name, value]) => element.setAttribute(name, value));
  element.append(...children);
  return element;
}

function renderDelegations() {
  document.getElementById("delegationList")
    .replaceChildren(...me.delegations.map(title => createElement("li", { text: title })));
}

const AUTH_METHODS = {
  kep: { label: "Рутокен ЭЦП 3.0 + ПИН КЭП", control: "Подтверждено (ГОСТ-Р)" },
  password: { label: "Логин и пароль защищённого контура", control: "Проверено (пароль)" }
};

const SESSION_STATUSES = {
  active: { label: "Активный сеанс", color: "green" },
  logout: { label: "Завершён штатно (Выход)", color: "blue" },
  timeout: { label: "Завершён штатно (Таймаут)", color: "blue" },
  forced: { label: "Завершён принудительно", color: "orange" }
};

function renderAudit() {
  const rows = me.audit.sessions.map(session => {
    const method = AUTH_METHODS[session.method];
    const status = SESSION_STATUSES[session.status];
    const p = moscowParts(session.startedAt);

    const time = createElement("td", {},
      ...(session.status === "active" ? [createElement("i", { className: "dot" })] : []),
      createElement("b", {}, `${p.day}.${p.month}.${p.year}`, document.createElement("br"), `${p.hour}:${p.minute}:${p.second}`)
    );

    return createElement("tr", {},
      time,
      createElement("td", { text: session.ip ?? "—" }),
      createElement("td", { text: method.label }),
      createElement("td", {}, createElement("span", { className: "status green", text: method.control })),
      createElement("td", {}, createElement("span", {
        className: `status ${status.color}`,
        text: session.current ? "Текущий активный сеанс" : status.label
      })),
      createElement("td", {}, session.current ? createElement("small", { text: "Текущий узел" }) : "")
    );
  });

  document.getElementById("auditBody").replaceChildren(...rows);
}

async function refreshMe() {
  try {
    me = await api("/api/me");
    bindData();
  } catch (error) {
    if (error.status === 401) location.reload();
  }
}

function showScreen(name) {
  landingApp.hidden = name !== "landing";
  adminApp.hidden = name !== "admin";
  commanderApp.hidden = name !== "commander";
  gaApp.hidden = name !== "ga";
  window.scrollTo(0, 0);
}

function openLanding() {
  showScreen("landing");
  history.replaceState(null, "", location.pathname + location.search);
}

function showAdminTab(tabName) {
  const selectedView = document.querySelector(
    `.admin-view[data-view="${tabName}"]`
  );
  if (!selectedView) return;

  adminViews.forEach(view => {
    view.hidden = view !== selectedView;
  });

  adminButtons.forEach(button => {
    button.classList.toggle("active", button.dataset.adminTab === tabName);
  });

  breadcrumbSection.textContent = tabSections[tabName] || DEFAULT_SECTION;
  breadcrumbTitle.textContent = tabTitles[tabName] || "Раздел";
  history.replaceState(null, "", `#${tabName}`);
  window.scrollTo(0, 0);

  if (tabName === "profile") refreshMe();
}

function openCommander() {
  showScreen("commander");
  history.replaceState(null, "", "#commander");
}

function openAdmin(tabName = DEFAULT_TAB) {
  if (me?.user.role === "commander") {
    openCommander();
    return;
  }
  if (me?.user.role === "admin") {
    openGa();
    return;
  }
  showScreen("admin");
  showAdminTab(tabName);
}

function enterApp(hash = "") {
  document.body.dataset.role = me.user.role;
  bindData();

  if (ROLE_SCREEN[me.user.role] === "ga") {
    openGa(hash.startsWith("ga-") ? hash.slice(3) : DEFAULT_GA_TAB);
  } else if (ROLE_SCREEN[me.user.role] === "commander" || hash === "commander") {
    openCommander();
  } else {
    openAdmin(tabTitles[hash] ? hash : DEFAULT_TAB);
  }
}

async function logout(everywhere = false) {
  try {
    await api(everywhere ? "/api/auth/logout-all" : "/api/auth/logout", { method: "POST" });
  } finally {
    location.replace(location.pathname);
  }
}

function showGaTab(tabName) {
  const key = GA_TABS.includes(tabName) ? tabName : DEFAULT_GA_TAB;

  gaViews.forEach(view => {
    view.hidden = view.dataset.gaView !== key;
  });
  gaButtons.forEach(button => {
    if (button.closest(".ga-nav")) button.classList.toggle("active", button.dataset.gaTab === key);
  });

  history.replaceState(null, "", `#ga-${key}`);
  window.scrollTo(0, 0);

  if (key === "rbac") loadGaUsers();
  if (key === "audit") loadGaAudit();
}

function openGa(tabName = DEFAULT_GA_TAB) {
  showScreen("ga");
  showGaTab(tabName);
}

const ROLE_BADGES = {
  admin: "SU / ROOT АДМИНИСТРАТОР",
  hq: "Ответственный за ГО (НШ)",
  head: "Руководитель / зам. по ГОЧС",
  commander: "Командир формирования (НФГО)"
};

const AUDIT_METHODS = { kep: "КЭП (ГОСТ Р 34.10)", password: "Логин и пароль" };

const formatTime = timestamp => {
  const p = moscowParts(timestamp);
  return `${p.hour}:${p.minute}:${p.second}`;
};

function showGaError(bodyId, columns, error) {
  if (error.status === 401 || error.status === 403) {
    location.reload();
    return;
  }
  document.getElementById(bodyId).replaceChildren(
    createElement("tr", {}, createElement("td", { className: "ga-empty", text: error.message, attrs: { colspan: columns } }))
  );
}

function userRow(user) {
  const cert = user.certificate
    ? [createElement("b", { text: `№ ${user.certificate.serialNumber}` }),
       createElement("small", { text: `Действителен до ${formatDate(user.certificate.validTo)}` })]
    : [createElement("small", { text: "Не выдан" })];

  const last = user.lastLogin
    ? [createElement("b", { text: `${formatDate(user.lastLogin.at)} ${formatTime(user.lastLogin.at)} MSK` }),
       createElement("small", { text: `IP: ${user.lastLogin.ip ?? "—"}` })]
    : [createElement("small", { text: "Входов не было" })];

  const reset = createElement("button", {
    className: "ga-btn danger-outline",
    text: user.activeSessions ? `Сбросить сеансы (${user.activeSessions})` : "Нет активных сеансов",
    attrs: { type: "button", "data-reset-user": user.id, "data-reset-name": user.fullName }
  });
  reset.disabled = !user.activeSessions;

  return createElement("tr", {},
    createElement("td", {}, createElement("b", { text: user.fullName }),
      createElement("small", { text: `Таб. № ${user.personnelNumber ?? "—"} • Логин: ${user.login}` })),
    createElement("td", {}, createElement("b", { text: user.department ?? "—" }), createElement("small", { text: user.position })),
    createElement("td", {}, createElement("span", { className: `ga-role-badge ${user.role}`, text: ROLE_BADGES[user.role] ?? user.role })),
    createElement("td", {}, ...cert),
    createElement("td", {}, ...last),
    createElement("td", {}, createElement("span", { className: "ga-tag gray", text: user.tokenModel ?? "Пароль" }),
      ...(user.locked ? [createElement("span", { className: "status red", text: "ЗАБЛОКИРОВАН" })] : [])),
    createElement("td", {}, reset)
  );
}

async function loadGaUsers() {
  try {
    const data = await api("/api/admin/users");
    document.getElementById("gaUsersBody").replaceChildren(...data.users.map(userRow));
    document.getElementById("gaUsersTotal").textContent = data.total;
    document.getElementById("gaUsersRoles").textContent = data.roles;
    document.getElementById("gaUsersSessions").textContent = `${data.activeSessions} активных сессий`;
    document.getElementById("gaUsersFoot").textContent = `Показано ${data.users.length} из ${data.total} записей`;
  } catch (error) {
    showGaError("gaUsersBody", 7, error);
  }
}

document.getElementById("gaUsersBody").addEventListener("click", async event => {
  const button = event.target.closest("[data-reset-user]");
  if (!button) return;
  if (!confirm(`Завершить все активные сеансы пользователя «${button.dataset.resetName}»?`)) return;

  button.disabled = true;
  try {
    await api(`/api/admin/users/${button.dataset.resetUser}/reset-sessions`, { method: "POST" });
  } catch (error) {
    if (error.status === 401 || error.status === 403) location.reload();
  }
  loadGaUsers();
});

function auditRow(item) {
  const subject = item.user?.fullName ?? item.identifier ?? "Неопознанный субъект";
  const subjectNote = [item.user?.login, item.ip && `IP ${item.ip}`].filter(Boolean).join(" • ");
  const stamp = createElement("small", { className: "ga-ts", text: new Date(item.at).toISOString() });

  return createElement("tr", {},
    createElement("td", {}, createElement("b", { className: "ga-ts", text: formatTime(item.at) }),
      createElement("small", { text: `${formatDate(item.at)} • ID #${item.id}` })),
    createElement("td", {}, createElement("span", { className: `ga-lvl ${item.level}`, text: `${item.level} (EID: ${item.eid})` })),
    createElement("td", {}, createElement("b", { text: subject }), createElement("small", { text: subjectNote || "—" })),
    createElement("td", {}, createElement("b", { text: item.category }), createElement("small", { text: item.title })),
    createElement("td", {}, createElement("code", { text: item.details ?? "—" })),
    createElement("td", {}, createElement("b", { text: AUDIT_METHODS[item.method] ?? "—" }), stamp),
    createElement("td", {}, createElement("span", { className: "ga-icons", text: "▤" }))
  );
}

const gaAuditSearch = document.getElementById("gaAuditSearch");
const gaAuditCriticalOnly = document.getElementById("gaAuditCriticalOnly");
let gaAuditRequest = 0;

async function loadGaAudit() {
  const request = ++gaAuditRequest;
  const query = new URLSearchParams({ limit: "50" });
  if (gaAuditSearch.value.trim()) query.set("q", gaAuditSearch.value.trim());
  if (gaAuditCriticalOnly.checked) query.set("critical", "1");

  try {
    const data = await api(`/api/admin/audit?${query}`);
    if (request !== gaAuditRequest) return;

    const rows = data.items.length
      ? data.items.map(auditRow)
      : [createElement("tr", {}, createElement("td", { className: "ga-empty", text: "Записей не найдено.", attrs: { colspan: 7 } }))];
    document.getElementById("gaAuditBody").replaceChildren(...rows);

    document.getElementById("gaAuditTotal24").textContent = data.last24h;
    document.getElementById("gaAuditTotal").textContent = data.total;
    document.getElementById("gaAuditCritical").textContent = data.critical24h;
    document.getElementById("gaAuditFound").textContent = `Отображено ${data.items.length} из ${data.matching} записей`;

    const days = data.lastCriticalAt ? Math.floor((Date.now() - data.lastCriticalAt) / 86400000) : null;
    document.getElementById("gaAuditCriticalNote").textContent =
      days === null ? "Критических событий не зарегистрировано"
        : days === 0 ? "Последняя тревога: сегодня" : `Последняя тревога: ${days} дн. назад`;
    const badge = document.getElementById("gaAuditCriticalBadge");
    badge.textContent = data.critical24h ? "ВНИМАНИЕ" : "В НОРМЕ";
    badge.className = `ga-tag ${data.critical24h ? "red" : "green"}`;
  } catch (error) {
    if (request === gaAuditRequest) showGaError("gaAuditBody", 7, error);
  }
}

let gaAuditTimer;
gaAuditSearch.addEventListener("input", () => {
  clearTimeout(gaAuditTimer);
  gaAuditTimer = setTimeout(loadGaAudit, 300);
});
gaAuditCriticalOnly.addEventListener("change", loadGaAudit);
document.querySelector('[data-ga-refresh="audit"]').addEventListener("click", loadGaAudit);
document.getElementById("gaAuditReset").addEventListener("click", () => {
  gaAuditSearch.value = "";
  gaAuditCriticalOnly.checked = false;
  loadGaAudit();
});

gaButtons.forEach(button => {
  button.addEventListener("click", () => showGaTab(button.dataset.gaTab));
});

document.querySelectorAll("[data-dismiss]").forEach(button => {
  button.addEventListener("click", () => {
    button.closest(".ga-banner").hidden = true;
  });
});

function selectAuthTab(name) {
  authTabs.forEach(tab => {
    tab.setAttribute("aria-selected", String(tab.dataset.authTab === name));
  });
  authPanels.forEach(panel => {
    panel.hidden = panel.dataset.authPanel !== name;
  });
}

function setMessage(panel, type, text) {
  const message = panel.querySelector(".auth-message");
  message.hidden = !text;
  message.className = `auth-message ${type}`;
  message.textContent = text;
}

function openAuth(tabName = "password") {
  selectAuthTab(tabName);
  if (!authDialog.open) authDialog.showModal();
}

document.querySelectorAll("[data-open-auth]").forEach(button => {
  button.addEventListener("click", () => {
    openAuth(button.dataset.openAuth || "password");
  });
});

document.querySelectorAll("[data-close-auth]").forEach(button => {
  button.addEventListener("click", () => authDialog.close());
});

authDialog.addEventListener("click", event => {
  if (event.target === authDialog) authDialog.close();
});

authDialog.addEventListener("close", () => {
  authPanels.forEach(panel => setMessage(panel, "", ""));
});

authTabs.forEach(tab => {
  tab.addEventListener("click", () => selectAuthTab(tab.dataset.authTab));
});

document.querySelectorAll("[data-toggle-secret]").forEach(button => {
  button.addEventListener("click", () => {
    const input = button.closest(".auth-input").querySelector("input");
    input.type = input.type === "password" ? "text" : "password";
  });
});

document.querySelectorAll("[data-auth-info]").forEach(button => {
  button.addEventListener("click", () => {
    setMessage(button.closest(".auth-panel"), "info", button.dataset.authInfo);
  });
});

const pinAttemptsLabel = document.getElementById("pinAttempts");

function lockKepForm(form) {
  form.querySelector('input[name="secret"]').disabled = true;
  form.querySelector('[type="submit"]').disabled = true;
}

document.querySelectorAll("[data-auth-form]").forEach(form => {
  form.addEventListener("submit", async event => {
    event.preventDefault();

    const data = new FormData(form);
    const method = form.dataset.authForm;
    const credentials = {
      method,
      role: data.get("role"),
      identifier: (data.get("identifier") || "").trim(),
      tokenSerial: data.get("tokenSerial"),
      secret: data.get("secret")
    };

    const submit = form.querySelector('[type="submit"]');
    submit.disabled = true;
    setMessage(form, "info", "Проверка учётных данных…");

    try {
      me = await api("/api/auth/login", { method: "POST", body: credentials });
      form.reset();
      authDialog.close();
      enterApp();
    } catch (error) {
      setMessage(form, "error", error.message);

      if (method === "kep" && error.data) {
        if (typeof error.data.attemptsLeft === "number") {
          pinAttemptsLabel.textContent = error.data.attemptsLeft;
        }
        if (error.data.locked) {
          lockKepForm(form);
          return;
        }
      }
      submit.disabled = false;
    }
  });
});

const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

function setActiveLandingLink(id) {
  landingNavLinks.forEach(link => {
    link.classList.toggle("active", link.dataset.jump === id);
  });
}

document.querySelectorAll("[data-jump]").forEach(link => {
  link.addEventListener("click", event => {
    event.preventDefault();
    const target = document.getElementById(link.dataset.jump);
    if (!target) return;

    target.scrollIntoView({
      behavior: prefersReducedMotion.matches ? "auto" : "smooth",
      block: "start"
    });
    setActiveLandingLink(link.dataset.jump);
  });
});

const sectionObserver = new IntersectionObserver(
  entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) setActiveLandingLink(entry.target.id);
    });
  },
  { rootMargin: "-25% 0px -65% 0px" }
);

landingNavLinks.forEach(link => {
  const section = document.getElementById(link.dataset.jump);
  if (section) sectionObserver.observe(section);
});

adminButtons.forEach(button => {
  button.addEventListener("click", () => showAdminTab(button.dataset.adminTab));
});

document.querySelectorAll("[data-open-commander]").forEach(button => {
  button.addEventListener("click", openCommander);
});

document.querySelectorAll("[data-return-admin]").forEach(button => {
  button.addEventListener("click", event => {
    event.preventDefault();
    openAdmin(button.dataset.returnAdmin);
  });
});

document.querySelectorAll("[data-logout]").forEach(button => {
  button.addEventListener("click", () => logout(button.dataset.logout === "all"));
});

scrollButtons.forEach(button => {
  button.addEventListener("click", () => {
    const target = document.getElementById(button.dataset.scroll);
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    scrollButtons.forEach(item => {
      item.classList.toggle("active", item === button);
    });
  });
});

function markDone(button, text) {
  button.textContent = text;
  button.disabled = true;
}

document.getElementById("markPresent").addEventListener("click", event => {
  markDone(event.currentTarget, "Отметки добавлены");
});

document.querySelectorAll(".plain-button").forEach(button => {
  button.addEventListener("click", () => markDone(button, "Действие отмечено"));
});

async function start() {
  const hash = location.hash.slice(1);

  try {
    const session = await api("/api/session");
    if (session.authenticated) {
      me = session.me;
      enterApp(hash);
      return;
    }
  } catch {
      }
  openLanding();
}

window.addEventListener("hashchange", () => {
  if (me) enterApp(location.hash.slice(1));
});

start();

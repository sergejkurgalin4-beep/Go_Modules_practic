// Встроенный SQLite (node:sqlite) доступен без флагов начиная с Node.js 22.13.
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 13)) {
  console.error(`Нужен Node.js 22.13 или новее, сейчас установлен ${process.versions.node}. Скачать: https://nodejs.org`);
  process.exit(1);
}

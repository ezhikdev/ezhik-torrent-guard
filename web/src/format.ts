const plural = (n: number, forms: [string, string, string]) => {
  const a = Math.abs(n) % 100;
  const b = a % 10;
  if (a > 10 && a < 20) return forms[2];
  if (b > 1 && b < 5) return forms[1];
  if (b === 1) return forms[0];
  return forms[2];
};

export const pl = (n: number, forms: [string, string, string]) => `${n} ${plural(n, forms)}`;

export function ago(ts?: number | null) {
  if (!ts) return '—';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 45) return 'только что';
  if (s < 3600) return `${Math.round(s / 60)} мин назад`;
  if (s < 86400) return `${Math.round(s / 3600)} ч назад`;
  if (s < 30 * 86400) return `${Math.round(s / 86400)} дн назад`;
  return dateShort(ts);
}

export function until(ts?: number | null) {
  if (!ts) return '—';
  const s = ts - Date.now() / 1000;
  if (s <= 0) return 'истёк';
  if (s < 3600) return `через ${Math.max(1, Math.round(s / 60))} мин`;
  if (s < 86400) return `через ${Math.round(s / 3600)} ч`;
  return `через ${pl(Math.round(s / 86400), ['день', 'дня', 'дней'])}`;
}

export function daysLeft(ts?: number | null) {
  if (!ts) return null;
  return Math.floor((ts - Date.now() / 1000) / 86400);
}

const dtf = new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
const df = new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: 'short', year: 'numeric' });
const tf = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit' });
const dmf = new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: 'short' });

export const dateTime = (ts?: number | null) => (ts ? dtf.format(ts * 1000) : '—');
export const dateShort = (ts?: number | null) => (ts ? df.format(ts * 1000) : '—');
export const timeShort = (ts: number) => tf.format(ts * 1000);
export const dayMonth = (ts: number) => dmf.format(ts * 1000);

export function duration(seconds?: number | null) {
  if (seconds == null) return '—';
  if (seconds === 0) return 'бессрочно';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (d) parts.push(`${d} д`);
  if (h) parts.push(`${h} ч`);
  if (m && !d) parts.push(`${m} мин`);
  return parts.join(' ') || `${seconds} с`;
}

export function uptime(seconds?: number | null) {
  if (!seconds) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d} д ${h} ч`;
  if (h) return `${h} ч ${m} мин`;
  return `${m} мин`;
}

export function bytes(n?: number | null) {
  if (n == null) return '—';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function bits(n?: number | null) {
  if (n == null) return '—';
  const units = ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с'];
  let i = 0;
  let v = n;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export const num = (n?: number | null) => (n == null ? '—' : new Intl.NumberFormat('ru-RU').format(n));

export const TYPE_LABEL: Record<string, string> = {
  torrent: 'Торрент',
  p2p: 'P2P / DHT',
  scan: 'Сканирование',
  node: 'Нода',
  cert: 'Сертификат',
  sanction: 'Блокировка',
  system: 'Система',
};

export const ACTION_LABEL: Record<string, { text: string; tone: string }> = {
  QUEUED: { text: 'Блокировка', tone: 'bad' },
  EXISTS: { text: 'Уже заблокирован', tone: 'warn' },
  OBSERVE: { text: 'Наблюдение', tone: 'accent' },
  PROTECTED: { text: 'Защищённый', tone: '' },
  NOT_CONFIGURED: { text: 'Remnawave не настроен', tone: 'warn' },
  STALE: { text: 'Устарело', tone: '' },
  FEATURE_OFF: { text: 'Выключено на ноде', tone: '' },
  FROZEN: { text: 'Заморожен', tone: 'bad' },
  BLOCKED: { text: 'Заблокирован', tone: 'bad' },
  UNFROZEN: { text: 'Разблокирован', tone: 'ok' },
  RELEASED: { text: 'Разблокирован вручную', tone: 'ok' },
  SKIPPED: { text: 'Пропущено', tone: '' },
  FAILED: { text: 'Ошибка', tone: 'bad' },
};

export const REASON_LABEL: Record<string, string> = {
  torrent: 'BitTorrent',
  p2p: 'P2P / DHT',
  scan: 'Сканирование портов',
  manual: 'Вручную',
  bittorrent: 'BitTorrent',
  'port-scan': 'Сканирование портов',
};

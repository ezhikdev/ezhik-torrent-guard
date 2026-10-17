import { Fragment } from 'preact';
import { useState } from 'preact/hooks';
import { ACTION_LABEL, TYPE_LABEL, ago, dateTime } from '../format';
import { Icon } from './Icon';
import { Badge, Link } from './ui';

const TYPE_ICON: Record<string, string> = {
  torrent: 'magnet',
  p2p: 'network',
  scan: 'radar',
  node: 'server',
  cert: 'certificate',
  sanction: 'ban',
  system: 'settings',
};

const SEVERITY_TONE: Record<string, string> = { error: 'bad', warn: 'warn', info: '' };

function Details({ event }: { event: any }) {
  const d = event.data || {};
  const rows: [string, any][] = [];
  if (d.socket) {
    rows.push(['Сокет', `${String(d.socket.protocol).toUpperCase()} :${d.socket.local_port} → ${d.socket.remote_ip}:${d.socket.remote_port}`]);
    rows.push(['Точных BT-сокетов', d.exact_sockets]);
  }
  if (d.window_seconds) {
    rows.push(['Окно', `${d.window_seconds} с`]);
    rows.push(['Назначений / IP / портов', `${d.unique_endpoints} / ${d.unique_ips} / ${d.unique_ports}`]);
  }
  for (const [k, v] of Object.entries(d.details || {})) rows.push([k, String(v)]);
  if (d.node_ip) rows.push(['IP ноды', d.node_ip]);
  if (d.detail) rows.push(['Детали', String(d.detail)]);
  rows.push(['Время', dateTime(event.detected_at)]);
  const samples: any[] = d.sample_endpoints || [];
  return (
    <div class="event__details">
      <dl class="kv">
        {rows.map(([k, v]) => (
          <Fragment key={k}>
            <dt>{k}</dt>
            <dd class="mono">{v}</dd>
          </Fragment>
        ))}
      </dl>
      {samples.length > 0 && (
        <div class="sample-grid mono tiny">
          {samples.slice(0, 60).map((s, i) => (
            <span key={i}>{String(s.protocol).toUpperCase()} {s.remote_ip}:{s.remote_port}</span>
          ))}
          {samples.length > 60 && <span class="faint">ещё {samples.length - 60}…</span>}
        </div>
      )}
    </div>
  );
}

export function EventRow({ event, compact }: { event: any; compact?: boolean }) {
  const [open, setOpen] = useState(false);
  const action = event.action ? ACTION_LABEL[event.action] : null;
  const detection = ['torrent', 'p2p', 'scan'].includes(event.type);
  const tone = detection ? event.type : SEVERITY_TONE[event.severity] || 'neutral';
  return (
    <div class={`event ${open ? 'is-open' : ''}`}>
      <button type="button" class="event__main" onClick={() => setOpen(!open)}>
        <span class={`event__icon event__icon--${tone}`}>
          <Icon name={TYPE_ICON[event.type] || 'info'} size={16} />
        </span>
        <div class="grow">
          <div class="event__title ellipsis">{event.title || TYPE_LABEL[event.type]}</div>
          <div class="event__meta">
            <span>{TYPE_LABEL[event.type] || event.type}</span>
            {event.node_name && (
              <span>
                · <Link to={`/nodes/${event.node_id}`}>{event.node_name}</Link>
              </span>
            )}
            {event.client_id && (
              <span>
                · клиент <Link to={`/sanctions?client=${event.client_id}`} class="mono">#{event.client_id}</Link>
              </span>
            )}
          </div>
        </div>
        {action && !compact && <Badge tone={action.tone} size="sm">{action.text}</Badge>}
        {action && compact && action.tone === 'bad' && <Badge tone="bad" size="sm">{action.text}</Badge>}
        <span class="event__time" title={dateTime(event.detected_at)}>{ago(event.detected_at)}</span>
      </button>
      {open && <Details event={event} />}
    </div>
  );
}

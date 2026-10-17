import { useState } from 'preact/hooks';
import { api } from '../api';
import { Legend, StackedBars } from '../components/charts';
import { EventRow } from '../components/events';
import { Icon } from '../components/Icon';
import { Badge, Callout, Empty, ErrorState, Link, Loading, Meter, PageHead, Segmented, StatusDot, useData } from '../components/ui';
import { ago, dayMonth, daysLeft, num, pl, timeShort } from '../format';
import { navigate } from '../state';

export const EVENT_SERIES = [
  { key: 'torrent', label: 'Торренты', color: 'var(--c-1)' },
  { key: 'p2p', label: 'P2P / DHT', color: 'var(--c-2)' },
  { key: 'scan', label: 'Сканирование', color: 'var(--c-3)' },
];

const MODE_LABEL: Record<string, string> = { enforce: 'блокировка', observe: 'наблюдение' };

function Kpi({ icon, tone, value, label, extra, to }: { icon: string; tone?: string; value: any; label: string; extra?: any; to?: string }) {
  return (
    <div class={`card ${to ? 'card--interactive' : ''}`} onClick={to ? () => navigate(to) : undefined}>
      <div class="stat">
        <div class="stat__top">
          <span class={`stat__icon ${tone ? `stat__icon--${tone}` : ''}`}>
            <Icon name={icon} size={18} />
          </span>
          {extra}
        </div>
        <div class="stat__value">{value}</div>
        <div class="stat__label">{label}</div>
      </div>
    </div>
  );
}

export function Dashboard() {
  const [range, setRange] = useState<'24h' | '7d' | '30d'>('24h');
  const { data, error, loading, reload } = useData(() => api.get(`/api/dashboard?range=${range}`), [range], 20000);

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  const d = data!;

  const DETECTIONS = ['torrent', 'p2p', 'scan'];
  const total = (c: any) => DETECTIONS.reduce((s, k) => s + (c?.[k]?.total || 0), 0);
  const blocked = (c: any) => DETECTIONS.reduce((s, k) => s + (c?.[k]?.blocked || 0), 0);
  const detections = total(d.counts);
  const prevDetections = total(d.prev_counts) - detections;
  const delta = prevDetections > 0 ? Math.round(((detections - prevDetections) / prevDetections) * 100) : null;

  // Build a dense bucket list so empty hours are visible.
  const byBucket: Record<number, Record<string, number>> = {};
  for (const row of d.series) {
    (byBucket[row.bucket] ||= {})[row.type] = row.c;
  }
  const buckets = [];
  const now = Date.now() / 1000;
  for (let ts = Math.floor(d.since / d.bucket) * d.bucket; ts <= now; ts += d.bucket) {
    buckets.push({ ts, values: byBucket[ts] || {} });
  }
  const formatX = d.bucket < 86400 && range === '24h' ? timeShort : dayMonth;

  return (
    <div class="stack">
      <PageHead
        title="Обзор"
        sub="Состояние защиты всей инфраструктуры"
        actions={
          <Segmented value={range} onChange={setRange} options={[
            { value: '24h', label: '24 часа' }, { value: '7d', label: '7 дней' }, { value: '30d', label: '30 дней' },
          ]} />
        }
      />

      {!d.remnawave_configured && (
        <Callout tone="warn" icon="alert">
          <b>Remnawave не подключён.</b> Обнаружения записываются, но блокировки не выполняются.{' '}
          <Link to="/settings/remnawave" class="link">Подключить →</Link>
        </Callout>
      )}
      {d.nodes.total === 0 && (
        <div class="card card--dots">
          <Empty icon="server" title="Добавьте первую ноду" action={<Link to="/nodes?add=1" class="btn btn--primary"><Icon name="plus" size={17} /><span>Добавить ноду</span></Link>}>
            Панель сгенерирует одну команду — выполните её на сервере с RemnaNode. Старая версия Torrent Guard будет удалена автоматически.
          </Empty>
        </div>
      )}
      {d.update && (
        <Callout icon="sparkles">
          Доступна новая версия панели <b>{d.update.version}</b>. <Link to="/settings/updates" class="link">Обновить →</Link>
        </Callout>
      )}

      <div class="grid grid--4">
        <Kpi icon="server" tone={d.nodes.offline ? 'bad' : 'ok'} to="/nodes"
          value={<>{d.nodes.online}<small> / {d.nodes.total}</small></>}
          label="нод на связи"
          extra={d.nodes.offline ? <Badge tone="bad" size="sm">{d.nodes.offline} офлайн</Badge> : d.nodes.problems ? <Badge tone="warn" size="sm">{d.nodes.problems} с проблемами</Badge> : <Badge tone="ok" size="sm">всё в порядке</Badge>} />
        <Kpi icon="radar" to="/events" value={num(detections)} label={`обнаружений за ${range === '24h' ? 'сутки' : range === '7d' ? '7 дней' : '30 дней'}`}
          extra={delta != null ? <span class={`delta ${delta > 0 ? 'delta--up' : delta < 0 ? 'delta--down' : ''}`}>{delta > 0 ? '+' : ''}{delta}%</span> : null} />
        <Kpi icon="ban" tone={d.sanctions.active ? 'warn' : undefined} to="/sanctions" value={num(d.sanctions.active)}
          label="пользователей заблокировано сейчас"
          extra={<span class="tiny faint">{num(blocked(d.counts))} блокировок за период</span>} />
        <Kpi icon="certificate" tone={d.certificates.expiring.length || d.certificates.failed ? 'warn' : 'ok'} to="/certificates"
          value={num(d.certificates.total)} label="SSL-сертификатов"
          extra={d.certificates.expiring.length ? <Badge tone="warn" size="sm">{d.certificates.expiring.length} истекают</Badge> : d.certificates.failed ? <Badge tone="bad" size="sm">ошибки</Badge> : null} />
      </div>

      <div class="grid grid--main">
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-title">Обнаружения</div>
              <div class="tiny faint" style={{ marginTop: '3px' }}>
                Торренты: {MODE_LABEL[d.modes.torrent]} · P2P: {d.p2p_enabled ? MODE_LABEL[d.modes.p2p] : 'выключено'} · Сканирование: {MODE_LABEL[d.modes.scan]}
              </div>
            </div>
            <Legend series={EVENT_SERIES} />
          </div>
          <StackedBars buckets={buckets} series={EVENT_SERIES} formatX={formatX} height={240}
            empty={<span><Icon name="shield" size={16} /> Нарушений не обнаружено</span>} />
          <div class="kpi-strip">
            {EVENT_SERIES.map((s) => (
              <div key={s.key}>
                <div class="row" style={{ gap: '6px' }}><span class="legend__swatch" style={{ background: s.color }} /><span class="tiny muted">{s.label}</span></div>
                <div class="num kpi-strip__value">{num(d.counts[s.key]?.total || 0)}</div>
                <div class="tiny faint">{num(d.counts[s.key]?.blocked || 0)} блокировок</div>
              </div>
            ))}
          </div>
        </div>

        <div class="card card--flush">
          <div class="card-head" style={{ padding: '18px 20px 0' }}>
            <div class="card-title">Ноды</div>
            <Link to="/nodes" class="btn btn--plain btn--sm"><span>Все</span><Icon name="arrowRight" size={15} /></Link>
          </div>
          <div class="node-mini-list">
            {d.node_cards.length === 0 && <div class="small faint" style={{ padding: '10px 20px 20px' }}>Ноды ещё не добавлены</div>}
            {d.node_cards.slice(0, 9).map((n: any) => (
              <Link to={`/nodes/${n.id}`} class="node-mini" key={n.id}>
                <StatusDot state={n.status === 'pending' ? 'idle' : !n.online ? 'bad' : n.problems.length ? 'warn' : 'ok'} />
                <div class="grow">
                  <div class="ellipsis node-mini__name">{n.name}</div>
                  <div class="tiny faint ellipsis">{n.status === 'pending' ? 'ожидает установки' : n.online ? n.ip : `офлайн · ${ago(n.last_seen_at)}`}</div>
                </div>
                {n.online && (
                  <div class="node-mini__meters">
                    <span class="tiny faint">CPU</span><Meter value={n.metrics?.cpu} />
                    <span class="tiny faint">RAM</span><Meter value={n.metrics?.mem_total ? (100 * n.metrics.mem_used) / n.metrics.mem_total : null} />
                  </div>
                )}
              </Link>
            ))}
          </div>
        </div>
      </div>

      <div class="grid grid--main">
        <div class="card card--flush">
          <div class="card-head" style={{ padding: '18px 20px 6px' }}>
            <div class="card-title">Последние события</div>
            <Link to="/events" class="btn btn--plain btn--sm"><span>Журнал</span><Icon name="arrowRight" size={15} /></Link>
          </div>
          {d.recent.length === 0 ? (
            <Empty icon="shield" title="Пока тихо">События защиты, состояния нод и сертификатов появятся здесь.</Empty>
          ) : (
            <div class="event-list">{d.recent.map((e: any) => <EventRow event={e} key={e.id} compact />)}</div>
          )}
        </div>
        <div class="stack">
          <div class="card">
            <div class="card-head">
              <div class="card-title">Частые нарушители</div>
              <span class="tiny faint">за период</span>
            </div>
            {d.top_clients.length === 0 ? (
              <div class="small faint">Нет нарушений</div>
            ) : (
              <div class="top-list">
                {d.top_clients.map((c: any) => (
                  <Link to={`/sanctions?client=${c.client_id}`} class="top-list__row" key={c.client_id}>
                    <span class="mono">#{c.client_id}</span>
                    <span class="grow tiny faint ellipsis">{String(c.types).split(',').map((t: string) => EVENT_SERIES.find((s) => s.key === t)?.label || t).join(', ')}</span>
                    <b class="num">{c.c}</b>
                  </Link>
                ))}
              </div>
            )}
          </div>
          {d.certificates.expiring.length > 0 && (
            <div class="card">
              <div class="card-head"><div class="card-title">Истекающие сертификаты</div></div>
              {d.certificates.expiring.map((c: any) => {
                const left = daysLeft(c.not_after) ?? 0;
                return (
                  <Link to={`/certificates/${c.id}`} class="top-list__row" key={c.id}>
                    <Icon name="certificate" size={16} />
                    <span class="grow ellipsis">{c.name}</span>
                    <Badge tone={left < 7 ? 'bad' : 'warn'} size="sm">{left < 0 ? 'истёк' : pl(left, ['день', 'дня', 'дней'])}</Badge>
                  </Link>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

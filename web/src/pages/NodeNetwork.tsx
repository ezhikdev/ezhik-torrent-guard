import { useState } from 'preact/hooks';
import { api } from '../api';
import { Icon } from '../components/Icon';
import {
  Badge, Button, Callout, CodeBox, Field, Link, Modal, Segmented, Switch, ToggleRow, confirmDialog, useAction, useData,
} from '../components/ui';
import { ago, num } from '../format';
import { POLICY_OPTIONS, RuleModal, Rule } from './Firewall';
import { openPreview } from './Sites';

const TRANSPORTS = [
  { value: 'grpc', label: 'gRPC' },
  { value: 'ws', label: 'WebSocket' },
  { value: 'httpupgrade', label: 'HTTPUpgrade' },
  { value: 'xhttp', label: 'XHTTP' },
];

/* ------------------------------------------------------------------ firewall */

export function FirewallCard({ node, onSaved }: { node: any; onSaved: () => void }) {
  const { busy, run } = useAction();
  const [adding, setAdding] = useState<Rule | null | undefined>(undefined);
  const plan = node.firewall || {};
  const override = node.firewall_override || {};
  const state = node.firewall_state || {};
  const save = (next: any, label: string) => run('fw', async () => {
    await api.patch(`/api/nodes/${node.id}`, { firewall: { ...override, ...next } });
    onSaved();
  }, label);
  const setPolicy = (key: string, policy: string | null) => {
    const ports = { ...(override.ports || {}) };
    if (policy) ports[key] = policy; else delete ports[key];
    save({ ports }, 'Политика порта сохранена');
  };
  const toggle = async (on: boolean) => {
    if (on && !(await confirmDialog({
      title: 'Включить firewall?',
      text: 'Всё, что не разрешено в таблице, будет закрыто. SSH остаётся открытым; если нода потеряет связь с панелью, правила откатятся автоматически.',
      confirm: 'Включить',
    }))) return;
    save({ enabled: on }, on ? 'Firewall включается' : 'Firewall выключается');
  };
  const extra: Rule[] = override.rules || [];
  const entries: any[] = plan.entries || [];
  return (
    <div class="card card--flush">
      <div class="card-head" style={{ padding: '18px 20px 6px' }}>
        <div>
          <div class="card-title row" style={{ gap: '8px' }}>
            <Icon name="shield" size={17} /> Firewall
            {state.active ? <Badge tone="ok" size="sm">активен</Badge> : <Badge size="sm">выключен</Badge>}
          </div>
          <div class="tiny faint">
            {override.enabled == null ? 'по глобальной настройке' : 'задано для ноды'}
            {state.active ? ` · отброшено пакетов: ${num(state.dropped_packets || 0)}` : ''}
          </div>
        </div>
        <div class="row row--wrap">
          {override.enabled != null && <Button size="sm" variant="plain" onClick={() => save({ enabled: null }, 'Используется глобальная настройка')}>Как глобально</Button>}
          <Switch on={!!plan.enabled} disabled={busy === 'fw'} onChange={toggle} />
          <Link to="/firewall" class="btn btn--plain btn--sm">Глобальные правила</Link>
        </div>
      </div>
      <div style={{ padding: '4px 20px 0' }} class="stack">
        {(plan.warnings || []).map((w: string) => <Callout tone="warn" key={w}>{w}</Callout>)}
        {node.components?.firewall && !node.components.firewall.ok && <Callout tone="bad">{node.components.firewall.message}</Callout>}
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Порт</th><th>Служба</th><th>Источник</th><th>Политика</th></tr></thead>
          <tbody>
            <tr>
              <td class="mono">tcp/{(plan.ssh || [22]).join(', ')}</td>
              <td>SSH</td><td class="small faint">защита от блокировки</td>
              <td><Badge tone="ok" size="sm">всегда открыт</Badge></td>
            </tr>
            {entries.map((e) => (
              <tr key={e.key}>
                <td class="mono">{e.key}</td>
                <td>{e.label}{e.process && e.process !== e.role && <span class="tiny faint"> · {e.process}</span>}</td>
                <td class="small faint">{e.origin}</td>
                <td>
                  {e.role === 'panel' ? <Badge tone="ok" size="sm">открыт (панель)</Badge> : (
                    <div class="row" style={{ gap: '6px' }}>
                      <Segmented value={e.policy} options={POLICY_OPTIONS} onChange={(v) => setPolicy(e.key, v)} />
                      {override.ports?.[e.key] && <button type="button" class="icon-btn icon-btn--sm" title="Сбросить к авто" onClick={() => setPolicy(e.key, null)}><Icon name="rotate" size={13} /></button>}
                    </div>
                  )}
                </td>
              </tr>
            ))}
            {entries.length === 0 && <tr><td colSpan={4} class="small faint">Агент ещё не прислал список открытых портов</td></tr>}
          </tbody>
        </table>
      </div>
      <div style={{ padding: '14px 20px 18px' }}>
        <div class="eyebrow" style={{ marginBottom: '8px' }}>Правила только для этой ноды</div>
        {extra.map((r) => (
          <div class="row row--between small" key={r.id} style={{ padding: '4px 0' }}>
            <span><Badge size="sm">{r.proto === 'any' ? 'TCP+UDP' : r.proto.toUpperCase()}</Badge> <span class="mono">{r.ports}</span>
              <span class="faint"> · {r.sources.length ? r.sources.join(', ') : 'все'}</span>{r.comment && <span class="muted"> · {r.comment}</span>}</span>
            <button type="button" class="icon-btn icon-btn--sm icon-btn--danger" title="Удалить" onClick={() => save({ rules: extra.filter((x) => x.id !== r.id) }, 'Правило удалено')}><Icon name="trash" size={14} /></button>
          </div>
        ))}
        <Button size="sm" icon="plus" onClick={() => setAdding(null)}>Добавить правило</Button>
      </div>
      {adding !== undefined && <RuleModal onClose={() => setAdding(undefined)} onSave={(rule) => { setAdding(undefined); save({ rules: [...extra, rule] }, 'Правило добавлено'); }} />}
    </div>
  );
}

/* --------------------------------------------------------------------- nginx */

function RouteModal({ route, onSave, onClose }: { route?: any; onSave: (r: any) => void; onClose: () => void }) {
  const [r, setR] = useState<any>(route || { transport: 'grpc', public_port: 443, upstream_host: '127.0.0.1', upstream_port: '', service_name: '', path: '', enabled: true });
  const set = (k: string, v: any) => setR({ ...r, [k]: v });
  const grpc = r.transport === 'grpc';
  return (
    <Modal title={route ? 'Маршрут' : 'Новый маршрут'} desc="Nginx принимает TLS и передаёт запрос во внутренний inbound Xray без TLS (security: none)" onClose={onClose}>
      <div class="stack">
        <Field label="Транспорт"><Segmented value={r.transport} options={TRANSPORTS} onChange={(v) => set('transport', v)} /></Field>
        <div class="form-grid">
          <Field label="Публичный порт Nginx"><input class="input" type="number" value={r.public_port} onInput={(e) => set('public_port', Number(e.currentTarget.value))} /></Field>
          {grpc
            ? <Field label="serviceName" hint="Как в Xray, без слэшей"><input class="input input--mono" value={r.service_name} onInput={(e) => set('service_name', e.currentTarget.value)} placeholder="cdn-service" /></Field>
            : <Field label="Путь" hint="Как в Xray, например /ws"><input class="input input--mono" value={r.path} onInput={(e) => set('path', e.currentTarget.value)} placeholder="/ws" /></Field>}
          <Field label="Адрес Xray"><input class="input input--mono" value={r.upstream_host} onInput={(e) => set('upstream_host', e.currentTarget.value)} /></Field>
          <Field label="Порт Xray"><input class="input" type="number" value={r.upstream_port} onInput={(e) => set('upstream_port', Number(e.currentTarget.value))} placeholder="10443" /></Field>
        </div>
        <p class="tiny faint">REALITY, RAW/TCP, mKCP и QUIC не проходят через HTTP-проксирование — такие inbound оставьте в режиме Direct на отдельном порту.</p>
        <div class="form-actions">
          <Button variant="plain" onClick={onClose}>Отмена</Button>
          <Button variant="primary" disabled={!r.upstream_port || (grpc ? !r.service_name : !r.path)} onClick={() => onSave(r)}>Сохранить</Button>
        </div>
      </div>
    </Modal>
  );
}

function SyncModal({ node, routeId, onClose, onDone }: { node: any; routeId: string; onClose: () => void; onDone: () => void }) {
  const { data, error, loading } = useData(() => api.post(`/api/nodes/${node.id}/nginx/remnawave-sync`, { route_id: routeId }), [routeId]);
  const { busy, run } = useAction();
  return (
    <Modal wide title="Синхронизация с Remnawave" desc="Изменяется только один inbound профиля: listen, port, security: none и serviceName/path. Остальной профиль и подписки не затрагиваются." onClose={onClose}>
      <div class="stack">
        {loading && <div class="small faint">Загрузка профиля…</div>}
        {error && <Callout tone="bad">{error}</Callout>}
        {data && (
          <>
            <div class="small">Профиль <b>{data.profile}</b>, inbound <span class="mono">{data.inbound}</span></div>
            {data.shared_with?.length > 1 && <Callout tone="warn">Этот профиль используют ноды: {data.shared_with.join(', ')}. Изменение применится ко всем.</Callout>}
            <div class="grid grid--2">
              <div><div class="eyebrow">Сейчас</div><CodeBox copy={false} text={JSON.stringify(data.before, null, 2)} /></div>
              <div><div class="eyebrow">Станет</div><CodeBox copy={false} text={JSON.stringify(data.after, null, 2)} /></div>
            </div>
          </>
        )}
        <div class="form-actions">
          <Button variant="plain" onClick={onClose}>Отмена</Button>
          <Button variant="primary" disabled={!data} loading={busy === 'sync'} onClick={() => run('sync', async () => {
            await api.post(`/api/nodes/${node.id}/nginx/remnawave-sync`, { route_id: routeId, inbound_tag: data.inbound, confirm: true });
            onDone();
          }, 'Профиль Remnawave обновлён')}>Применить в Remnawave</Button>
        </div>
      </div>
    </Modal>
  );
}

export function NginxCard({ node, onSaved }: { node: any; onSaved: () => void }) {
  const { busy, run } = useAction();
  const [editing, setEditing] = useState<any>(undefined);
  const [syncing, setSyncing] = useState<string | null>(null);
  const cfg = node.nginx || { mode: 'direct', routes: [] };
  const state = node.nginx_state || {};
  const checks: Record<string, any> = Object.fromEntries((node.route_checks || []).map((c: any) => [c.route_id, c]));
  const save = (next: any, label: string) => run('ng', async () => {
    await api.patch(`/api/nodes/${node.id}`, { nginx: { ...cfg, ...next } });
    onSaved();
  }, label);
  const setMode = async (mode: string) => {
    if (mode === cfg.mode) return;
    if (mode === 'frontend' && !cfg.routes.length && !(await confirmDialog({ title: 'Включить Nginx без маршрутов?', text: 'Nginx займёт 80/443 и будет показывать сайт-заглушку. VPN-маршруты можно добавить позже.', confirm: 'Включить' }))) return;
    if (mode === 'direct' && !(await confirmDialog({ title: 'Отключить Nginx Frontend?', text: 'Клиенты, подключающиеся через маршруты Nginx, потеряют связь, пока inbound не будет переведён на публичный порт.', confirm: 'Отключить', danger: true }))) return;
    save({ mode }, mode === 'frontend' ? 'Nginx настраивается на ноде' : 'Nginx отключается');
  };
  const failed = node.components?.nginx && !node.components.nginx.ok;
  return (
    <div class="card card--flush">
      <div class="card-head" style={{ padding: '18px 20px 6px' }}>
        <div>
          <div class="card-title row" style={{ gap: '8px' }}><Icon name="network" size={17} /> Nginx</div>
          <div class="tiny faint">{cfg.mode === 'frontend' ? `Frontend · ${cfg.server_name || node.domain || 'без домена'}` : 'Direct — Xray слушает порты сам, Nginx не используется'}</div>
        </div>
        <Segmented value={cfg.mode} options={[{ value: 'direct', label: 'Direct' }, { value: 'frontend', label: 'Frontend' }]} onChange={setMode} />
      </div>
      <div style={{ padding: '4px 20px 0' }} class="stack">
        {failed && <Callout tone="bad">{node.components.nginx.message}</Callout>}
        {cfg.mode === 'frontend' && !node.cert_id && <Callout tone="warn">Сертификат для ноды не выбран — Nginx использует самоподписанный. Назначьте сертификат в карточке «SSL-сертификат».</Callout>}
        {state.checks?.length > 0 && <div class="tiny muted">Проверка {ago(state.at)}: {state.checks.join(' · ')}</div>}
      </div>
      {cfg.mode === 'frontend' && (
        <>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Вкл</th><th>Маршрут</th><th>→ Xray</th><th>Совместимость</th><th class="col-actions" /></tr></thead>
              <tbody>
                {cfg.routes.length === 0 && <tr><td colSpan={5} class="small faint">Маршрутов нет — Nginx показывает только сайт-заглушку</td></tr>}
                {cfg.routes.map((r: any) => {
                  const c = checks[r.id];
                  return (
                    <tr key={r.id}>
                      <td><Switch on={r.enabled} onChange={(v) => save({ routes: cfg.routes.map((x: any) => (x.id === r.id ? { ...x, enabled: v } : x)) }, 'Сохранено')} /></td>
                      <td><Badge size="sm">{TRANSPORTS.find((t) => t.value === r.transport)?.label}</Badge> <span class="mono small">:{r.public_port} {r.transport === 'grpc' ? `/${r.service_name}/Tun` : r.path}</span></td>
                      <td class="mono small">{r.upstream_host}:{r.upstream_port}{c?.inbound && <div class="tiny faint">{c.inbound}</div>}</td>
                      <td class="small">
                        {!c ? '—' : c.ok ? <Badge tone="ok" size="sm">ок</Badge> : c.problems.map((p: string) => <div class="bad-text tiny" key={p}>{p}</div>)}
                        {c?.notes?.map((p: string) => <div class="tiny faint" key={p}>{p}</div>)}
                      </td>
                      <td class="col-actions">
                        <div class="row" style={{ gap: '4px' }}>
                          {c && !c.ok && c.inbound && <Button size="sm" variant="soft" onClick={() => setSyncing(r.id)}>Исправить в Remnawave</Button>}
                          <button type="button" class="icon-btn icon-btn--sm" title="Изменить" onClick={() => setEditing(r)}><Icon name="edit" size={14} /></button>
                          <button type="button" class="icon-btn icon-btn--sm icon-btn--danger" title="Удалить" onClick={() => save({ routes: cfg.routes.filter((x: any) => x.id !== r.id) }, 'Маршрут удалён')}><Icon name="trash" size={14} /></button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div style={{ padding: '12px 20px 18px' }} class="stack">
            <div class="row row--wrap">
              <Button size="sm" icon="plus" loading={busy === 'ng'} onClick={() => setEditing(null)}>Добавить маршрут</Button>
              <Button size="sm" variant="plain" icon="refresh" onClick={() => run('rw', async () => { await api.post('/api/remnawave/refresh'); onSaved(); }, 'Данные Remnawave обновлены')}>Обновить из Remnawave</Button>
            </div>
            {!node.remnawave && <div class="tiny faint">Нода не сопоставлена с Remnawave (по адресу). Укажите UUID или адрес ноды Remnawave в «Параметры».</div>}
            <ToggleRow title="Редирект HTTP → HTTPS" desc="Порт 80 отвечает 301 на https" on={cfg.http_redirect} onChange={(v) => save({ http_redirect: v }, 'Сохранено')} />
            <ToggleRow title="Не проверять чужие конфигурации Nginx" desc="Включайте, только если уверены, что другие server-блоки не слушают те же порты" on={cfg.force} onChange={(v) => save({ force: v }, 'Сохранено')} />
          </div>
        </>
      )}
      {editing !== undefined && <RouteModal route={editing || undefined} onClose={() => setEditing(undefined)} onSave={(route) => {
        setEditing(undefined);
        save({ routes: editing ? cfg.routes.map((x: any) => (x.id === route.id ? route : x)) : [...cfg.routes, route] }, 'Маршрут сохранён — Nginx применит его через несколько секунд');
      }} />}
      {syncing && <SyncModal node={node} routeId={syncing} onClose={() => setSyncing(null)} onDone={() => { setSyncing(null); onSaved(); }} />}
    </div>
  );
}

/* --------------------------------------------------------------- BBR + site */

export function NetworkSiteCard({ node, onSaved }: { node: any; onSaved: () => void }) {
  const { data: sites } = useData(() => api.get('/api/sites'), []);
  const { run } = useAction();
  const patch = (body: any, label: string) => run('x', async () => { await api.patch(`/api/nodes/${node.id}`, body); onSaved(); }, label);
  const bbr = node.bbr == null ? 'default' : node.bbr ? 'on' : 'off';
  const bs = node.bbr_state || {};
  const installed = node.site_state?.version;
  return (
    <div class="card">
      <div class="card-head"><div class="card-title">Сеть и сайт</div></div>
      <div class="toggle-row">
        <div class="toggle-row__text">
          <div class="toggle-row__title row" style={{ gap: '8px' }}><Icon name="zap" size={16} /> TCP BBR</div>
          <div class="toggle-row__desc">Сейчас: <span class="mono">{bs.congestion || '—'}</span>{bs.qdisc && <> / <span class="mono">{bs.qdisc}</span></>}</div>
        </div>
        <Segmented value={bbr} options={[{ value: 'default', label: 'Как глобально' }, { value: 'on', label: 'Вкл' }, { value: 'off', label: 'Выкл' }]}
          onChange={(v) => patch({ bbr: v === 'default' ? null : v === 'on' }, 'Сохранено')} />
      </div>
      <div class="divider" />
      <Field label="Сайт-заглушка" hint={node.nginx?.mode === 'frontend' ? `Установлено: ${installed || '—'}` : 'Используется только в режиме Nginx Frontend'}>
        <div class="row">
          <select class="select grow" value={node.site_id || ''} onChange={(e) => patch({ site_id: e.currentTarget.value || null }, 'Сайт назначен')}>
            <option value="">Глобальный сайт{sites?.default ? '' : ' (встроенная страница)'}</option>
            {(sites?.sites || []).map((s: any) => <option value={s.id} key={s.id}>{s.name}</option>)}
          </select>
          <Button icon="eye" onClick={() => openPreview(`/api/nodes/${node.id}/site-preview`)}>Предпросмотр</Button>
        </div>
      </Field>
      {node.nginx?.mode === 'frontend' && node.components?.site && !node.components.site.ok && <Callout tone="bad">{node.components.site.message}</Callout>}
    </div>
  );
}

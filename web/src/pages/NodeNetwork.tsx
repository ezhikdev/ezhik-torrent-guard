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

const MODE_LABEL: Record<string, string> = { direct: 'Direct', frontend: 'Frontend', vision: 'Vision + TLS' };

function visionCandidates(node: any) {
  return (node.remnawave?.inbounds || []).filter((i: any) => i.type === 'vless' && i.security !== 'reality'
    && ['raw', 'tcp'].includes(String(i.network || 'raw')));
}

function VisionSetupModal({ node, onClose, onSave }: { node: any; onClose: () => void; onSave: (v: any) => void }) {
  const current = node.nginx?.vision || {};
  const candidates = visionCandidates(node);
  const [v, setV] = useState<any>({ http1_port: 8001, h2_port: 8002, h2: true, proxy_protocol: true, ...current,
    inbound_tag: current.inbound_tag || candidates[0]?.tag || '' });
  const set = (k: string, val: any) => setV({ ...v, [k]: val });
  const on443 = (node.remnawave?.inbounds || []).filter((i: any) => i.port === 443 && i.tag !== v.inbound_tag);
  return (
    <Modal wide title="Vision + TLS Fallback" desc="Xray принимает TLS на 443 (VLESS RAW + XTLS Vision). Клиенты VLESS получают туннель, обычные HTTPS-посетители — сайт-заглушку Nginx через fallback." onClose={onClose}>
      <div class="stack">
        {!node.remnawave && <Callout tone="warn">Нода не сопоставлена с Remnawave — выбрать inbound нельзя. {node.remnawave_status}</Callout>}
        {node.remnawave && candidates.length === 0 && <Callout tone="warn">На ноде нет подходящего VLESS inbound (RAW, без REALITY). Создайте отдельный inbound для Vision в профиле Remnawave — REALITY и gRPC/WS/XHTTP inbound'ы не трогаются.</Callout>}
        {on443.length > 0 && <Callout tone="bad">Порт 443 уже занимает {on443.map((i: any) => `${i.tag} (${i.security})`).join(', ')} — Vision включить нельзя.</Callout>}
        <Field label="VLESS inbound для Vision" hint="Будет изменён только он: 443, TLS, flow xtls-rprx-vision, fallbacks на Nginx">
          <select class="select" value={v.inbound_tag} onChange={(e) => set('inbound_tag', e.currentTarget.value)}>
            {candidates.map((i: any) => <option value={i.tag} key={i.tag}>{i.tag} · порт {i.port} · {i.security || 'none'}</option>)}
          </select>
        </Field>
        <ToggleRow title="HTTP/2 для посетителей" desc="ALPN h2 → Nginx h2c. Нужен и для gRPC-маршрутов на 443" on={v.h2} onChange={(x) => set('h2', x)} />
        <ToggleRow title="PROXY protocol" desc="Nginx видит реальный IP посетителя (fallback xver 1)" on={v.proxy_protocol} onChange={(x) => set('proxy_protocol', x)} />
        <div class="form-grid">
          <Field label="Локальный порт HTTP/1.1"><input class="input" type="number" value={v.http1_port} onInput={(e) => set('http1_port', Number(e.currentTarget.value))} /></Field>
          <Field label="Локальный порт HTTP/2"><input class="input" type="number" value={v.h2_port} disabled={!v.h2} onInput={(e) => set('h2_port', Number(e.currentTarget.value))} /></Field>
        </div>
        <p class="tiny faint">Порядок безопасный: сначала агент освобождает 443 и поднимает Nginx на 127.0.0.1 (с проверкой и откатом), затем вы подтверждаете изменение inbound в Remnawave. gRPC/WS/XHTTP-маршруты на 443 продолжают работать через fallback, REALITY на других портах не меняется.</p>
        <div class="form-actions">
          <Button variant="plain" onClick={onClose}>Отмена</Button>
          <Button variant="primary" disabled={!v.inbound_tag || on443.length > 0} onClick={() => onSave(v)}>{node.nginx?.mode === 'vision' ? 'Сохранить' : 'Включить Vision'}</Button>
        </div>
      </div>
    </Modal>
  );
}

function VisionSyncModal({ node, onClose, onDone }: { node: any; onClose: () => void; onDone: () => void }) {
  const { data, error, loading } = useData(() => api.post(`/api/nodes/${node.id}/nginx/vision-sync`, {}), []);
  const { busy, run } = useAction();
  return (
    <Modal wide title="Vision: изменение inbound в Remnawave" desc="Меняется только выбранный inbound профиля. Пользователи, другие inbound'ы и другие ноды не затрагиваются." onClose={onClose}>
      <div class="stack">
        {loading && <div class="small faint">Загрузка профиля…</div>}
        {error && <Callout tone="bad">{error}</Callout>}
        {data && (
          <>
            <div class="small">Профиль <b>{data.profile}</b>, inbound <span class="mono">{data.inbound}</span></div>
            <ul class="small" style={{ margin: 0, paddingLeft: '18px' }}>{data.drift.map((d: string) => <li key={d}>{d}</li>)}</ul>
            {data.notes.map((n: string) => <Callout tone="warn" key={n}>{n}</Callout>)}
            <div class="grid grid--2">
              <div><div class="eyebrow">Сейчас</div><CodeBox copy={false} text={JSON.stringify(data.before, null, 2)} /></div>
              <div><div class="eyebrow">Станет</div><CodeBox copy={false} text={JSON.stringify(data.after, null, 2)} /></div>
            </div>
          </>
        )}
        <div class="form-actions">
          <Button variant="plain" onClick={onClose}>Отмена</Button>
          {data && !data.agent_ready && <Button variant="primary" loading={busy === 'w'} onClick={() => run('w', async () => {
            await api.post(`/api/nodes/${node.id}/nginx/vision-sync`, { confirm: true, when_ready: true }); onDone();
          }, 'Применится автоматически, как только Nginx будет готов')}>Применить, когда Nginx будет готов</Button>}
          {data?.agent_ready && <Button variant="primary" loading={busy === 's'} onClick={() => run('s', async () => {
            await api.post(`/api/nodes/${node.id}/nginx/vision-sync`, { confirm: true }); onDone();
          }, 'Inbound обновлён в Remnawave')}>Применить в Remnawave</Button>}
        </div>
      </div>
    </Modal>
  );
}

function VisionPanel({ node, onSaved, onEdit }: { node: any; onSaved: () => void; onEdit: () => void }) {
  const [syncing, setSyncing] = useState(false);
  const { run } = useAction();
  const c = node.vision_check || {};
  const v = node.nginx?.vision || {};
  const pending = node.vision_pending;
  const e2e = c.e2e || {};
  return (
    <div style={{ padding: '4px 20px 6px' }} class="stack">
      <dl class="kv">
        <dt>Inbound</dt><dd class="mono">{v.inbound_tag || '—'} → 0.0.0.0:443, TLS, xtls-rprx-vision</dd>
        <dt>Fallback</dt><dd class="mono small">HTTP/1.1 → 127.0.0.1:{v.http1_port}{v.h2 ? ` · h2 → 127.0.0.1:${v.h2_port}` : ''}{v.proxy_protocol ? ' · PROXY' : ''}</dd>
        <dt>Сертификат в Xray</dt><dd class="mono small">{c.cert_file || '—'}</dd>
        <dt>Состояние</dt><dd>{e2e.ok ? <Badge tone="ok" size="sm">работает</Badge> : <Badge tone="warn" size="sm">не готово</Badge>} <span class="small">{e2e.summary || 'агент ещё не проверял'}</span></dd>
      </dl>
      {(c.problems || []).map((p: string) => <Callout tone="bad" key={p}>{p}</Callout>)}
      {(c.drift || []).length > 0 && <div class="small">Нужно изменить в Remnawave: <span class="muted">{c.drift.join(' · ')}</span></div>}
      {(c.notes || []).map((p: string) => <div class="tiny faint" key={p}>{p}</div>)}
      {pending?.state === 'waiting' && <Callout icon="clock">Синхронизация подтверждена и выполнится, как только агент поднимет fallback Nginx. <Button size="sm" variant="plain" onClick={() => run('c', async () => { await api.post(`/api/nodes/${node.id}/nginx/vision-sync`, { cancel: true }); onSaved(); }, 'Отменено')}>Отменить</Button></Callout>}
      {pending?.state === 'failed' && <Callout tone="bad">Синхронизация не выполнена: {pending.error}</Callout>}
      <div class="row row--wrap">
        <Button size="sm" variant={c.drift?.length ? 'primary' : 'soft'} disabled={!c.drift?.length || (c.problems || []).length > 0} onClick={() => setSyncing(true)}>Синхронизировать с Remnawave</Button>
        <Button size="sm" variant="plain" icon="settings" onClick={onEdit}>Параметры Vision</Button>
        {c.ok && <Badge tone="ok" size="sm">inbound соответствует</Badge>}
      </div>
      {syncing && <VisionSyncModal node={node} onClose={() => setSyncing(false)} onDone={() => { setSyncing(false); onSaved(); }} />}
    </div>
  );
}

export function NginxCard({ node, onSaved }: { node: any; onSaved: () => void }) {
  const { busy, run } = useAction();
  const [editing, setEditing] = useState<any>(undefined);
  const [syncing, setSyncing] = useState<string | null>(null);
  const [visionSetup, setVisionSetup] = useState(false);
  const cfg = node.nginx || { mode: 'direct', routes: [] };
  const withNginx = cfg.mode === 'frontend' || cfg.mode === 'vision';
  const state = node.nginx_state || {};
  const checks: Record<string, any> = Object.fromEntries((node.route_checks || []).map((c: any) => [c.route_id, c]));
  const save = (next: any, label: string) => run('ng', async () => {
    await api.patch(`/api/nodes/${node.id}`, { nginx: { ...cfg, ...next } });
    onSaved();
  }, label);
  const setMode = async (mode: string) => {
    if (mode === cfg.mode) return;
    if (mode === 'vision') { setVisionSetup(true); return; }
    if (cfg.mode === 'vision' && !(await confirmDialog({ title: `Выйти из режима Vision?`, text: mode === 'frontend' ? 'Nginx снова займёт 443. Сначала верните inbound Vision с порта 443 в Remnawave — иначе агент откажется переключаться (порт занят Xray).' : 'Nginx перестанет отвечать на fallback: VPN-клиенты Vision продолжат работать, обычные HTTPS-посетители получат обрыв соединения вместо сайта.', confirm: 'Переключить', danger: true }))) return;
    if (mode === 'frontend' && !cfg.routes.length && !(await confirmDialog({ title: 'Включить Nginx без маршрутов?', text: 'Nginx займёт 80/443 и будет показывать сайт-заглушку. VPN-маршруты можно добавить позже.', confirm: 'Включить' }))) return;
    if (mode === 'direct' && cfg.mode === 'frontend' && !(await confirmDialog({ title: 'Отключить Nginx Frontend?', text: 'Клиенты, подключающиеся через маршруты Nginx, потеряют связь, пока inbound не будет переведён на публичный порт.', confirm: 'Отключить', danger: true }))) return;
    save({ mode }, mode === 'frontend' ? 'Nginx настраивается на ноде' : 'Nginx отключается');
  };
  const failed = node.components?.nginx && !node.components.nginx.ok;
  return (
    <div class="card card--flush">
      <div class="card-head" style={{ padding: '18px 20px 6px' }}>
        <div>
          <div class="card-title row" style={{ gap: '8px' }}><Icon name="network" size={17} /> Nginx</div>
          <div class="tiny faint">{cfg.mode === 'frontend' ? `Frontend · ${cfg.server_name || node.domain || 'без домена'}`
            : cfg.mode === 'vision' ? 'Vision + TLS Fallback — Xray на 443, обычные посетители попадают на сайт Nginx'
              : 'Direct — Xray слушает порты сам, Nginx не используется'}</div>
        </div>
        <Segmented value={cfg.mode} options={Object.entries(MODE_LABEL).map(([value, label]) => ({ value, label }))} onChange={setMode} />
      </div>
      <div style={{ padding: '4px 20px 0' }} class="stack">
        {failed && <Callout tone="bad">{node.components.nginx.message}</Callout>}
        {cfg.mode === 'frontend' && !node.cert_id && <Callout tone="warn">Сертификат для ноды не выбран — Nginx использует самоподписанный. Назначьте сертификат в карточке «SSL-сертификат».</Callout>}
        {withNginx && state.checks?.length > 0 && <div class="tiny muted">Проверка {ago(state.at)}: {state.checks.join(' · ')}</div>}
      </div>
      {cfg.mode === 'vision' && <VisionPanel node={node} onSaved={onSaved} onEdit={() => setVisionSetup(true)} />}
      {withNginx && (
        <>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Вкл</th><th>Маршрут</th><th>→ Xray</th><th>Совместимость</th><th class="col-actions" /></tr></thead>
              <tbody>
                {cfg.routes.length === 0 && <tr><td colSpan={5} class="small faint">Маршрутов нет — Nginx показывает только сайт-заглушку</td></tr>}
                {cfg.mode === 'vision' && cfg.routes.some((r: any) => r.public_port === 443) && <tr><td colSpan={5} class="tiny faint">Маршруты на 443 работают через fallback Xray → Nginx (TLS завершает Xray)</td></tr>}
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
              <Button size="sm" variant="plain" icon="refresh" onClick={() => run('rw', async () => { const r = await api.post('/api/remnawave/refresh'); onSaved(); if (r.error) throw new Error(r.error); }, 'Данные Remnawave обновлены')}>Обновить из Remnawave</Button>
            </div>
            {!node.remnawave && <div class="tiny bad-text">Нода не сопоставлена с Remnawave: {node.remnawave_status}</div>}
            <ToggleRow title="Редирект HTTP → HTTPS" desc="Порт 80 отвечает 301 на https" on={cfg.http_redirect} onChange={(v) => save({ http_redirect: v }, 'Сохранено')} />
            <ToggleRow title="Не проверять чужие конфигурации Nginx" desc="Включайте, только если уверены, что другие server-блоки не слушают те же порты" on={cfg.force} onChange={(v) => save({ force: v }, 'Сохранено')} />
          </div>
        </>
      )}
      {editing !== undefined && <RouteModal route={editing || undefined} onClose={() => setEditing(undefined)} onSave={(route) => {
        setEditing(undefined);
        save({ routes: editing ? cfg.routes.map((x: any) => (x.id === route.id ? route : x)) : [...cfg.routes, route] }, 'Маршрут сохранён — Nginx применит его через несколько секунд');
      }} />}
      {visionSetup && <VisionSetupModal node={node} onClose={() => setVisionSetup(false)} onSave={(vision) => {
        setVisionSetup(false);
        save({ mode: 'vision', vision }, 'Агент переключает Nginx на fallback-порты');
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
      <Field label="Сайт-заглушка" hint={['frontend', 'vision'].includes(node.nginx?.mode) ? `Установлено: ${installed || '—'}` : 'Используется в режимах Nginx Frontend и Vision + TLS'}>
        <div class="row">
          <select class="select grow" value={node.site_id || ''} onChange={(e) => patch({ site_id: e.currentTarget.value || null }, 'Сайт назначен')}>
            <option value="">Глобальный сайт{sites?.default ? '' : ' (встроенная страница)'}</option>
            {(sites?.sites || []).map((s: any) => <option value={s.id} key={s.id}>{s.name}</option>)}
          </select>
          <Button icon="eye" onClick={() => openPreview(`/api/nodes/${node.id}/site-preview`)}>Предпросмотр</Button>
        </div>
      </Field>
      {['frontend', 'vision'].includes(node.nginx?.mode) && node.components?.site && !node.components.site.ok && <Callout tone="bad">{node.components.site.message}</Callout>}
    </div>
  );
}

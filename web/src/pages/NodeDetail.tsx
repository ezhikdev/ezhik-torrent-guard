import { useEffect, useState } from 'preact/hooks';
import { api } from '../api';
import { Legend, LineChart, UptimeStrip } from '../components/charts';
import { EventRow } from '../components/events';
import { Icon } from '../components/Icon';
import {
  Badge, Button, Callout, CodeBox, Empty, ErrorState, Field, Loading, Menu, Meter, Modal, PageHead, Segmented,
  StatusDot, ToggleRow, confirmDialog, useAction, useData,
} from '../components/ui';
import { ago, bits, bytes, dateTime, dayMonth, timeShort, uptime } from '../format';
import { navigate, toast, useRoute } from '../state';
import { FirewallCard, NetworkSiteCard, NginxCard } from './NodeNetwork';
import { nodeState } from './Nodes';

const COMPONENT_LABEL: Record<string, string> = {
  legacy: 'Старые версии',
  network: 'Сеть',
  suricata: 'Сенсор Suricata',
  detector: 'Детектор',
  certificate: 'Сертификат',
  agent_update: 'Обновление агента',
  command: 'Команды',
};

function InstallCommand({ id }: { id: string }) {
  const [cmd, setCmd] = useState<any>(null);
  const { busy, run } = useAction();
  return cmd ? (
    <div class="stack stack--sm">
      <CodeBox text={cmd.command} />
      <div class="tiny faint">Одноразовая команда, действует до {dateTime(cmd.expires_at)}. Предыдущие команды для этой ноды больше не работают.</div>
    </div>
  ) : (
    <Button icon="terminal" loading={busy === 'cmd'} onClick={() => run('cmd', async () => setCmd(await api.post(`/api/nodes/${id}/install-command`)))}>
      Сгенерировать команду установки
    </Button>
  );
}

function MetricsCard({ id }: { id: string }) {
  const [period, setPeriod] = useState<'1h' | '6h' | '24h' | '7d'>('6h');
  const { data } = useData(() => api.get(`/api/nodes/${id}/metrics?period=${period}`), [id, period], 30000);
  const points = data?.points || [];
  const fmtX = period === '7d' ? dayMonth : timeShort;
  return (
    <div class="card">
      <div class="card-head">
        <div class="card-title">Ресурсы</div>
        <Segmented value={period} onChange={setPeriod} options={[
          { value: '1h', label: '1 ч' }, { value: '6h', label: '6 ч' }, { value: '24h', label: '24 ч' }, { value: '7d', label: '7 д' },
        ]} />
      </div>
      <div class="grid grid--2">
        <div>
          <div class="row row--between" style={{ marginBottom: '8px' }}>
            <span class="eyebrow">CPU и память, %</span>
            <Legend series={[{ key: 'cpu', label: 'CPU', color: 'var(--c-1)' }, { key: 'mem', label: 'RAM', color: 'var(--c-2)' }]} />
          </div>
          <LineChart points={points} max={100} formatY={(v) => `${Math.round(v)}%`} formatX={fmtX}
            series={[{ key: 'cpu', label: 'CPU', color: 'var(--c-1)' }, { key: 'mem', label: 'RAM', color: 'var(--c-2)' }]} />
        </div>
        <div>
          <div class="row row--between" style={{ marginBottom: '8px' }}>
            <span class="eyebrow">Сеть WAN</span>
            <Legend series={[{ key: 'rx', label: 'Входящий', color: 'var(--c-1)' }, { key: 'tx', label: 'Исходящий', color: 'var(--c-2)' }]} />
          </div>
          <LineChart points={points} formatY={(v) => bits(v)} formatX={fmtX}
            series={[{ key: 'rx', label: 'Входящий', color: 'var(--c-1)' }, { key: 'tx', label: 'Исходящий', color: 'var(--c-2)' }]} />
        </div>
      </div>
    </div>
  );
}

function CertCard({ node, onSaved }: { node: any; onSaved: () => void }) {
  const { data: certs } = useData(() => api.get('/api/certificates'), []);
  const [certId, setCertId] = useState(node.cert_id || '');
  const [domain, setDomain] = useState(node.domain || '');
  const [target, setTarget] = useState<any>({ mode: 'auto', dir: '/etc/xray/ssl', container: '', container_dir: '/etc/xray/ssl', apply: 'restart', command: '', ...node.cert_target });
  const { busy, run } = useAction();
  const list: any[] = certs?.certificates || [];
  const chosen = list.find((c) => c.id === certId);
  const covered = chosen && domain ? chosen.domains.some((d: string) => d === domain || (d.startsWith('*.') && domain.split('.').slice(1).join('.') === d.slice(2))) : null;
  const state = node.cert_state;

  const save = (extra: any = {}) =>
    run('save', async () => {
      await api.patch(`/api/nodes/${node.id}`, { cert_id: certId || null, domain, cert_target: target, ...extra });
      onSaved();
    }, 'Настройки сертификата сохранены');

  return (
    <div class="card">
      <div class="card-head">
        <div class="card-title">SSL-сертификат</div>
        {state?.error ? <Badge tone="bad">ошибка установки</Badge> : state?.id ? <Badge tone="ok">установлен v{state.version}</Badge> : node.cert_id ? <Badge>ожидает доставки</Badge> : <Badge>не назначен</Badge>}
      </div>
      {state?.error && <Callout tone="bad">{state.error}</Callout>}
      <div class="form-grid" style={{ marginTop: state?.error ? '14px' : 0 }}>
        <Field label="Сертификат">
          <select class="select" value={certId} onChange={(e) => setCertId(e.currentTarget.value)}>
            <option value="">— не использовать —</option>
            {list.map((c) => (
              <option value={c.id} key={c.id} disabled={!c.version}>{c.name} {c.version ? '' : '(не выпущен)'}</option>
            ))}
          </select>
        </Field>
        <Field label="Домен ноды (SNI)" hint={covered === false ? undefined : 'Для проверки покрытия сертификатом'}
          error={covered === false ? 'Сертификат не покрывает этот домен' : null}>
          <input class="input input--mono" value={domain} placeholder="de1.example.com" onInput={(e) => setDomain(e.currentTarget.value)} />
        </Field>
        <Field label="Куда устанавливать" hint="auto: контейнер Docker или systemd-юнит определяется сам">
          <select class="select" value={target.mode} onChange={(e) => setTarget({ ...target, mode: e.currentTarget.value })}>
            <option value="auto">Автоматически</option>
            <option value="docker">Docker-контейнер</option>
            <option value="systemd">systemd-сервис Xray</option>
            <option value="files">Только файлы на хосте</option>
          </select>
        </Field>
        <Field label="Применение" hint={target.apply === 'none' ? 'Xray перечитывает файлы сам, если в профиле задан ocspStapling' : 'Перезапуск кратко разрывает соединения'}>
          <select class="select" value={target.apply} onChange={(e) => setTarget({ ...target, apply: e.currentTarget.value })}>
            <option value="restart">Перезапустить контейнер/сервис</option>
            <option value="none">Без перезапуска (hot reload)</option>
            <option value="command">Своя команда</option>
          </select>
        </Field>
        <Field label="Каталог на хосте">
          <input class="input input--mono" value={target.dir} onInput={(e) => setTarget({ ...target, dir: e.currentTarget.value })} />
        </Field>
        <Field label="Каталог в контейнере">
          <input class="input input--mono" value={target.container_dir} onInput={(e) => setTarget({ ...target, container_dir: e.currentTarget.value })} />
        </Field>
        <Field label="Контейнер / юнит" hint="Пусто — как у ноды (remnanode)">
          <input class="input input--mono" value={target.container} placeholder={node.container} onInput={(e) => setTarget({ ...target, container: e.currentTarget.value })} />
        </Field>
        {target.apply === 'command' && (
          <Field label="Команда перезагрузки">
            <input class="input input--mono" value={target.command} placeholder="docker restart remnanode" onInput={(e) => setTarget({ ...target, command: e.currentTarget.value })} />
          </Field>
        )}
      </div>
      {state?.id && <div class="tiny faint" style={{ marginTop: '12px' }}>Установлен {ago(state.installed_at)} · действует до {state.not_after}</div>}
      <div class="form-actions">
        {node.cert_id && (
          <Button variant="danger-soft" onClick={async () => {
            const remove = await confirmDialog({ title: 'Отключить сертификат на ноде?', text: 'Панель перестанет управлять сертификатом. Файлы сертификата будут удалены с ноды, Xray будет перезапущен.', confirm: 'Отключить и удалить файлы', danger: true });
            if (remove) {
              setCertId('');
              save({ cert_id: null, cert_remove: true });
            }
          }}>Отключить</Button>
        )}
        <Button variant="primary" loading={busy === 'save'} onClick={() => save()}>Сохранить</Button>
      </div>
    </div>
  );
}

function SettingsModal({ node, onClose, onSaved }: { node: any; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState({
    name: node.name, tags: (node.tags || []).join(', '), notes: node.notes || '', container: node.container_override ?? '',
    interface: node.interface || '', wan_ip: node.wan_ip || '', remnawave_node: node.remnawave_node_hint || '',
  });
  const { busy, run } = useAction();
  const set = (k: string) => (e: any) => setForm({ ...form, [k]: e.currentTarget.value });
  return (
    <Modal title="Параметры ноды" onClose={onClose} wide>
      <div class="form-grid">
        <Field label="Название"><input class="input" value={form.name} onInput={set('name')} /></Field>
        <Field label="Теги" hint="Через запятую: de, premium"><input class="input" value={form.tags} onInput={set('tags')} /></Field>
        <Field label="Контейнер RemnaNode" hint="Пусто — автоопределение"><input class="input input--mono" value={form.container} placeholder={node.container} onInput={set('container')} /></Field>
        <Field label="WAN-интерфейс" hint="Пусто — по маршруту по умолчанию"><input class="input input--mono" value={form.interface} placeholder={node.facts?.wan_interface} onInput={set('interface')} /></Field>
        <Field label="Исходящий IPv4" hint="Если у сервера несколько адресов"><input class="input input--mono" value={form.wan_ip} placeholder={node.facts?.wan_ip} onInput={set('wan_ip')} /></Field>
        <Field label="Нода в Remnawave" hint={node.remnawave ? `Сопоставлена: ${node.remnawave.name}` : 'UUID или адрес. Пусто — по IP/домену'}><input class="input input--mono" value={form.remnawave_node} onInput={set('remnawave_node')} /></Field>
        <Field label="Заметки"><input class="input" value={form.notes} onInput={set('notes')} /></Field>
      </div>
      <div class="form-actions">
        <Button variant="plain" onClick={onClose}>Отмена</Button>
        <Button variant="primary" loading={busy === 's'} onClick={() => run('s', async () => {
          await api.patch(`/api/nodes/${node.id}`, { ...form, tags: form.tags.split(',').map((t: string) => t.trim()).filter(Boolean) });
          onSaved();
          onClose();
        }, 'Сохранено')}>Сохранить</Button>
      </div>
    </Modal>
  );
}

export function NodeDetail({ id }: { id: string }) {
  const { params } = useRoute();
  const { data: node, error, loading, reload } = useData(() => api.get(`/api/nodes/${id}`), [id], 8000);
  const { data: ev } = useData(() => api.get(`/api/events?node=${id}&limit=30`), [id], 20000);
  const { data: settings } = useData(() => api.get('/api/settings'), []);
  const [editing, setEditing] = useState(false);
  const { busy, run } = useAction();

  useEffect(() => {
    if (params.get('install') === '1') window.setTimeout(() => document.getElementById('install')?.scrollIntoView({ behavior: 'smooth' }), 300);
  }, []);

  if (loading && !node) return <Loading />;
  if (error && !node) return <ErrorState error={error} onRetry={reload} />;
  const n = node!;
  const st = nodeState(n);
  const m = n.metrics || {};
  const det = n.detector || {};
  const diag = n.diagnostics?.checks || [];
  const modes = settings?.protection;

  const command = (type: string, label: string) => run(type, () => api.post(`/api/nodes/${id}/command`, { type }), label);
  const patch = (body: any, label: string) => run('patch', async () => { await api.patch(`/api/nodes/${id}`, body); reload(true); }, label);

  return (
    <div class="stack">
      <PageHead
        crumbs={[{ label: 'Ноды', to: '/nodes' }, { label: n.name }]}
        title={<span class="row" style={{ gap: '12px' }}><StatusDot state={st.dot} />{n.name}</span>}
        sub={<>{st.text}{n.ip && <> · <span class="mono">{n.ip}</span></>}{n.os && <> · {n.os}</>}</>}
        actions={
          <>
            {n.update_available && !n.updating && (
              <Button variant="primary" icon="download" loading={busy === 'upd'} onClick={() => run('upd', async () => { await api.post(`/api/nodes/${id}/update`); reload(true); }, 'Обновление агента запущено')}>
                Обновить до {n.agent_latest}
              </Button>
            )}
            {n.updating && <Badge tone="accent"><span class="spinner" style={{ width: '12px', height: '12px' }} /> обновление → {n.agent_latest}</Badge>}
            <Button icon="stethoscope" loading={busy === 'diagnose'} disabled={!n.online} onClick={() => command('diagnose', 'Диагностика запрошена — результат появится через несколько секунд')}>Диагностика</Button>
            <Button icon="edit" onClick={() => setEditing(true)}>Параметры</Button>
            <Menu items={[
              { label: 'Перезапустить детектор', icon: 'rotate', onClick: () => command('restart_detector', 'Детектор перезапускается') },
              { label: 'Перезапустить Suricata', icon: 'rotate', onClick: () => command('restart_suricata', 'Suricata перезапускается') },
              { label: 'Пересинхронизировать', icon: 'refresh', onClick: () => command('resync', 'Конфигурация будет применена заново') },
              { label: 'Перезапустить агент', icon: 'power', onClick: () => command('restart_agent', 'Агент перезапустится') },
              'sep',
              n.status === 'disabled'
                ? { label: 'Включить ноду', icon: 'play', onClick: () => patch({ status: 'active' }, 'Нода включена') }
                : { label: 'Отключить защиту на ноде', icon: 'pause', onClick: () => patch({ status: 'disabled' }, 'Защита на ноде отключена') },
              { label: 'Удалить ноду', icon: 'trash', danger: true, onClick: async () => {
                const ok = await confirmDialog({
                  title: `Удалить ${n.name}?`,
                  text: n.online ? 'Агент удалит себя с сервера: сервисы, Suricata и настройки. RemnaNode и сертификаты Xray не затрагиваются.' : 'Нода офлайн — запись будет удалена сразу, а агент удалит себя сам, когда сервер снова выйдет на связь.',
                  confirm: 'Удалить', danger: true,
                });
                if (ok) run('del', async () => { await api.del(`/api/nodes/${id}?uninstall=true`); navigate('/nodes'); }, 'Нода удаляется');
              } },
            ]} />
          </>
        }
      />

      {n.status === 'pending' && (
        <div class="card card--dots" id="install">
          <div class="card-title" style={{ marginBottom: '10px' }}>Нода ожидает установки агента</div>
          <p class="small muted" style={{ marginBottom: '14px' }}>Выполните команду на сервере от root. Нода появится в сети автоматически.</p>
          <InstallCommand id={id} />
        </div>
      )}
      {n.status === 'removing' && <Callout tone="warn">Агент получает команду удаления. Если нода не на связи, запись можно удалить ещё раз — без деинсталляции.</Callout>}
      {n.legacy?.report && (
        <Callout tone="ok" icon="check">
          Старая версия Torrent Guard {n.legacy.removed_version || ''} удалена: {n.legacy.report.removed?.length || 0} объектов, архив настроек{' '}
          <span class="mono">{n.legacy.report.backup || '—'}</span>.
        </Callout>
      )}

      <div class="grid grid--3">
        <div class="card">
          <div class="card-head"><div class="card-title">Доступность</div><span class="tiny faint">48 часов</span></div>
          <UptimeStrip hours={n.uptime_strip || []} />
          <div class="avail-row">
            {(['24h', '7d', '30d'] as const).map((k) => (
              <div key={k}>
                <div class="num avail-row__value">{n.availability?.[k] == null ? '—' : `${n.availability[k]}%`}</div>
                <div class="tiny faint">{k === '24h' ? 'сутки' : k === '7d' ? '7 дней' : '30 дней'}</div>
              </div>
            ))}
          </div>
          <dl class="kv" style={{ marginTop: '14px' }}>
            <dt>Аптайм сервера</dt><dd>{uptime(m.uptime)}</dd>
            <dt>Последний контакт</dt><dd>{ago(n.last_seen_at)}</dd>
            <dt>Добавлена</dt><dd>{dateTime(n.created_at)}</dd>
          </dl>
        </div>
        <div class="card">
          <div class="card-head"><div class="card-title">Система</div></div>
          <dl class="kv">
            <dt>Хост</dt><dd class="mono">{n.hostname || '—'}</dd>
            <dt>ОС</dt><dd>{n.os || '—'}</dd>
            <dt>Ядро</dt><dd class="mono">{n.kernel || '—'}</dd>
            <dt>Docker</dt><dd>{n.docker || '—'}</dd>
            <dt>Контейнер</dt><dd><span class="mono">{n.container}</span> {n.container_state && <Badge size="sm" tone={n.container_state.status === 'running' ? 'ok' : 'bad'}>{n.container_state.status}</Badge>}</dd>
            <dt>Агент</dt><dd class="mono">{n.agent_version || '—'}</dd>
            <dt>Интерфейс</dt><dd class="mono">{n.facts?.wan_interface || '—'}</dd>
          </dl>
        </div>
        <div class="card">
          <div class="card-head"><div class="card-title">Нагрузка</div></div>
          <div class="res-list">
            <div><div class="row row--between small"><span>CPU · {m.cpu_count || '?'} ядер</span><b class="num">{Math.round(m.cpu ?? 0)}%</b></div><Meter value={m.cpu} /></div>
            <div><div class="row row--between small"><span>Память</span><b class="num">{bytes(m.mem_used)} / {bytes(m.mem_total)}</b></div><Meter value={m.mem_used} max={m.mem_total || 1} /></div>
            <div><div class="row row--between small"><span>Диск</span><b class="num">{bytes(m.disk_used)} / {bytes(m.disk_total)}</b></div><Meter value={m.disk_used} max={m.disk_total || 1} /></div>
            <div class="row row--between small"><span>Сеть ↓ / ↑</span><b class="num">{bits(m.rx_bps)} / {bits(m.tx_bps)}</b></div>
            <div class="row row--between small"><span>Load average</span><b class="num mono">{(m.load || []).join(' ') || '—'}</b></div>
          </div>
        </div>
      </div>

      <div class="grid grid--2">
        <div class="card">
          <div class="card-head">
            <div class="card-title">Защита на ноде</div>
            <a class="btn btn--plain btn--sm" href="/settings/protection" onClick={(e) => { e.preventDefault(); navigate('/settings/protection'); }}>Общие настройки</a>
          </div>
          <ToggleRow
            title={<span class="row" style={{ gap: '8px' }}><Icon name="magnet" size={17} /> Торренты и P2P</span>}
            desc={modes ? `Режим: ${modes.torrent.mode === 'enforce' ? 'блокировка' : 'наблюдение'} · заморозка ${Math.round(modes.torrent.freeze_seconds / 60)} мин` : ''}
            on={n.torrent_enabled} disabled={n.status !== 'active'}
            onChange={(v) => patch({ torrent_enabled: v }, v ? 'Защита от торрентов включена' : 'Защита от торрентов выключена')} />
          <ToggleRow
            title={<span class="row" style={{ gap: '8px' }}><Icon name="radar" size={17} /> Сканирование портов</span>}
            desc={modes ? `Режим: ${modes.scan.mode === 'enforce' ? 'блокировка' : 'наблюдение'}` : ''}
            on={n.scan_enabled} disabled={n.status !== 'active'}
            onChange={(v) => patch({ scan_enabled: v }, v ? 'Защита от сканирования включена' : 'Защита от сканирования выключена')} />
          <div class="divider" />
          <div class="eyebrow" style={{ marginBottom: '10px' }}>Компоненты</div>
          <div class="component-list">
            {Object.entries(n.components || {}).filter(([, c]: any) => c && (c.message || !c.ok)).map(([name, c]: any) => (
              <div class="component" key={name}>
                <Icon name={c.ok ? 'check' : 'alert'} size={15} class={c.ok ? 'ok-text' : 'bad-text'} />
                <span class="component__name">{COMPONENT_LABEL[name] || name}</span>
                <span class={`component__msg ${c.ok ? 'muted' : 'bad-text'}`}>{c.message || (c.ok ? 'OK' : 'ошибка')}</span>
              </div>
            ))}
            {Object.keys(n.components || {}).length === 0 && <div class="small faint">Агент ещё не прислал состояние компонентов</div>}
          </div>
          {det.stats && (
            <>
              <div class="divider" />
              <div class="det-stats">
                <div><b class="num">{det.stats.access ?? 0}</b><span>соединений</span></div>
                <div><b class="num">{det.stats.bound_sockets ?? 0}</b><span>сокетов</span></div>
                <div><b class="num">{det.stats.bt_alerts ?? 0}</b><span>nDPI-алертов</span></div>
                <div><b class="num">{(det.stats.torrent_events ?? 0) + (det.stats.p2p_events ?? 0) + (det.stats.scan_events ?? 0)}</b><span>нарушений</span></div>
              </div>
              <div class="tiny faint" style={{ marginTop: '8px' }}>Счётчики с момента запуска агента. Последняя строка логов Xray: {det.last_line_age?.access == null ? 'нет' : `${Math.round(det.last_line_age.access)} с назад`}</div>
            </>
          )}
        </div>

        <div class="card">
          <div class="card-head">
            <div class="card-title">Диагностика</div>
            <span class="tiny faint">{n.diagnostics_at ? ago(n.diagnostics_at) : 'ещё не выполнялась'}</span>
          </div>
          {diag.length === 0 ? (
            <Empty icon="stethoscope" title="Нет результатов">Запустите диагностику — агент проверит Docker, логи Xray, Suricata, сеть и время.</Empty>
          ) : (
            <div class="checks">
              {diag.map((c: any) => (
                <div class={`check check--${c.status}`} key={c.id}>
                  <span class="check__icon"><Icon name={c.status === 'ok' ? 'check' : c.status === 'warn' ? 'alert' : 'x'} size={14} /></span>
                  <div class="grow">
                    <div class="row row--between"><b class="small">{c.title}</b></div>
                    <div class="tiny muted">{c.message}</div>
                    {c.hint && c.status !== 'ok' && <div class="tiny check__hint">{c.hint}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {n.status !== 'pending' && <MetricsCard id={id} />}
      {n.status !== 'pending' && <CertCard node={n} onSaved={() => reload(true)} />}
      {n.status !== 'pending' && <NginxCard node={n} onSaved={() => reload(true)} />}
      {n.status !== 'pending' && (
        <div class="grid grid--2-1">
          <FirewallCard node={n} onSaved={() => reload(true)} />
          <NetworkSiteCard node={n} onSaved={() => reload(true)} />
        </div>
      )}

      <div class="card card--flush">
        <div class="card-head" style={{ padding: '18px 20px 6px' }}><div class="card-title">События ноды</div></div>
        {(ev?.events || []).length === 0 ? <Empty icon="shield" title="Событий нет" /> : (
          <div class="event-list">{ev.events.map((e: any) => <EventRow event={e} key={e.id} />)}</div>
        )}
      </div>

      {n.status !== 'pending' && (
        <details class="card">
          <summary class="card-title" style={{ cursor: 'pointer' }}>Переустановка агента</summary>
          <p class="small muted" style={{ margin: '10px 0 14px' }}>Если сервер переустановлен или агент удалён вручную — выполните новую команду. Нода сохранит историю.</p>
          <InstallCommand id={id} />
        </details>
      )}

      {editing && <SettingsModal node={n} onClose={() => setEditing(false)} onSaved={() => { reload(true); toast('Сохранено'); }} />}
    </div>
  );
}

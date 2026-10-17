import { useEffect, useMemo, useState } from 'preact/hooks';
import { api } from '../api';
import { Icon } from '../components/Icon';
import {
  Badge, Button, Callout, CodeBox, Empty, ErrorState, Field, Link, Loading, Menu, Meter, Modal, PageHead,
  Segmented, StatusDot, Switch, confirmDialog, useAction, useData,
} from '../components/ui';
import { ago, uptime } from '../format';
import { navigate, toast, toastError, useRoute } from '../state';

type Filter = 'all' | 'online' | 'offline' | 'problems' | 'outdated';

export function nodeState(n: any): { dot: 'ok' | 'bad' | 'warn' | 'idle'; text: string } {
  if (n.status === 'pending') return { dot: 'idle', text: 'Ожидает установки' };
  if (n.status === 'removing') return { dot: 'warn', text: 'Удаляется' };
  if (!n.online) return { dot: 'bad', text: `Офлайн · ${ago(n.last_seen_at)}` };
  if (n.status === 'disabled') return { dot: 'idle', text: 'Отключена' };
  if (n.updating) return { dot: 'warn', text: 'Обновляется' };
  if (n.problems?.length) return { dot: 'warn', text: 'Есть проблемы' };
  return { dot: 'ok', text: 'Работает' };
}

export function AddNodeModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [container, setContainer] = useState('');
  const [torrent, setTorrent] = useState(true);
  const [scan, setScan] = useState(true);
  const [result, setResult] = useState<any>(null);
  const [connected, setConnected] = useState<any>(null);
  const { busy, run } = useAction();

  useEffect(() => {
    if (!result || connected) return;
    const timer = setInterval(async () => {
      try {
        const node = await api.get(`/api/nodes/${result.node.id}`);
        if (node.status !== 'pending' && node.online) {
          setConnected(node);
          onCreated();
        }
      } catch {
        /* keep polling */
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [result, connected]);

  const create = () =>
    run('create', async () => {
      const r = await api.post('/api/nodes', { name, container: container || null, torrent_enabled: torrent, scan_enabled: scan });
      setResult(r);
      onCreated();
    });

  if (result) {
    return (
      <Modal title={connected ? 'Нода подключена' : `Установка агента: ${result.node.name}`} onClose={onClose} wide
        desc={connected ? undefined : 'Выполните команду на сервере ноды от root. Команда одноразовая и действует 24 часа.'}>
        {connected ? (
          <div class="stack">
            <Callout tone="ok" icon="check">
              <b>{connected.name}</b> на связи ({connected.ip}). Агент {connected.agent_version} получил настройки защиты и сейчас
              разворачивает компоненты — состояние видно на странице ноды.
            </Callout>
            <div class="form-actions">
              <Button variant="plain" onClick={onClose}>Закрыть</Button>
              <Button variant="primary" iconRight="arrowRight" onClick={() => navigate(`/nodes/${connected.id}`)}>Открыть ноду</Button>
            </div>
          </div>
        ) : (
          <div class="stack">
            <CodeBox text={result.install.command} />
            <div class="steps">
              <div class="step">
                <span class="step__num">1</span>
                <div class="step__body small">Подключитесь к серверу по SSH и вставьте команду. Нужны Ubuntu 22.04/24.04 и Docker с RemnaNode.</div>
              </div>
              <div class="step">
                <span class="step__num">2</span>
                <div class="step__body small">Если на сервере стоит старый Torrent Guard или SSL-агент, они будут удалены автоматически, активные блокировки перейдут в панель.</div>
              </div>
              <div class="step">
                <span class="step__num"><span class="spinner" /></span>
                <div class="step__body small">Ждём подключения агента… Окно можно закрыть — нода появится в списке сама.</div>
              </div>
            </div>
            <Callout icon="info">
              Агент подключается к панели по <span class="mono">{result.install.panel_url}</span>. Убедитесь, что этот порт открыт для нод.
            </Callout>
          </div>
        )}
      </Modal>
    );
  }

  return (
    <Modal title="Добавить ноду" desc="Панель создаст запись и одноразовую команду установки агента." onClose={onClose}>
      <div class="stack">
        <Field label="Название" hint="Например de-1 или «Франкфурт #2». Можно изменить позже.">
          <input class="input" value={name} autoFocus onInput={(e) => setName(e.currentTarget.value)} placeholder="de-1" />
        </Field>
        <Field label="Контейнер RemnaNode" hint="Оставьте пустым — агент найдёт контейнер remnanode сам.">
          <input class="input input--mono" value={container} onInput={(e) => setContainer(e.currentTarget.value)} placeholder="remnanode" />
        </Field>
        <div>
          <div class="toggle-row">
            <div class="toggle-row__text">
              <div class="toggle-row__title">Защита от торрентов</div>
              <div class="toggle-row__desc">Suricata + nDPI и детектор P2P/DHT</div>
            </div>
            <Switch on={torrent} onChange={setTorrent} />
          </div>
          <div class="toggle-row">
            <div class="toggle-row__text">
              <div class="toggle-row__title">Защита от сканирования портов</div>
              <div class="toggle-row__desc">Анализ назначений Xray по каждому клиенту</div>
            </div>
            <Switch on={scan} onChange={setScan} />
          </div>
        </div>
        <div class="form-actions">
          <Button variant="plain" onClick={onClose}>Отмена</Button>
          <Button variant="primary" icon="terminal" loading={busy === 'create'} disabled={!name.trim()} onClick={create}>Получить команду</Button>
        </div>
      </div>
    </Modal>
  );
}

export function Nodes() {
  const { params } = useRoute();
  const { data, error, loading, reload, setData } = useData(() => api.get('/api/nodes'), [], 10000);
  const [filter, setFilter] = useState<Filter>('all');
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [adding, setAdding] = useState(params.get('add') === '1');
  const { busy, run } = useAction();

  const nodes: any[] = data?.nodes || [];
  const counts = useMemo(() => ({
    online: nodes.filter((n) => n.online).length,
    offline: nodes.filter((n) => !n.online && n.status !== 'pending').length,
    problems: nodes.filter((n) => n.problems?.length).length,
    outdated: nodes.filter((n) => n.update_available).length,
  }), [nodes]);
  const visible = nodes.filter((n) => {
    const q = query.trim().toLowerCase();
    if (q && !`${n.name} ${n.ip || ''} ${n.hostname || ''} ${(n.tags || []).join(' ')}`.toLowerCase().includes(q)) return false;
    if (filter === 'online') return n.online;
    if (filter === 'offline') return !n.online && n.status !== 'pending';
    if (filter === 'problems') return n.problems?.length > 0;
    if (filter === 'outdated') return n.update_available;
    return true;
  });

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={reload} />;

  const toggleFeature = async (node: any, key: string, value: boolean) => {
    setData({ ...data, nodes: nodes.map((n) => (n.id === node.id ? { ...n, [key]: value } : n)) });
    try {
      await api.patch(`/api/nodes/${node.id}`, { [key]: value });
      toast(`${node.name}: ${key === 'torrent_enabled' ? 'защита от торрентов' : 'защита от сканирования'} ${value ? 'включена' : 'выключена'}`);
    } catch (e) {
      toastError(e);
    }
    reload(true);
  };

  const bulk = (action: string, value?: unknown, label = 'Готово') =>
    run(action, async () => {
      const r = await api.post('/api/nodes/bulk', { ids: [...selected], action, value });
      toast(`${label}: ${r.done.length}`);
      setSelected(new Set());
      reload(true);
    });

  const allChecked = visible.length > 0 && visible.every((n) => selected.has(n.id));

  return (
    <div class="stack">
      <PageHead
        title="Ноды"
        sub={`${nodes.length} всего · ${counts.online} на связи · агент ${data.agent_version}`}
        actions={
          <>
            {counts.outdated > 0 && (
              <Button icon="download" loading={busy === 'all'} onClick={async () => {
                if (await confirmDialog({ title: `Обновить агент на ${counts.outdated} нодах?`, text: `Ноды скачают агент ${data.agent_version} с панели, проверят контрольную сумму и перезапустятся. Защита прерывается на несколько секунд.`, confirm: 'Обновить' })) {
                  run('all', async () => {
                    const r = await api.post('/api/nodes/update-all');
                    toast(`Обновление запущено на ${r.done.length} нодах`);
                    reload(true);
                  });
                }
              }}>Обновить все ({counts.outdated})</Button>
            )}
            <Button variant="primary" icon="plus" onClick={() => setAdding(true)}>Добавить ноду</Button>
          </>
        }
      />

      <div class="toolbar">
        <div class="input-group toolbar__search">
          <Icon name="search" size={16} />
          <input class="input" placeholder="Поиск по имени, IP, тегу" value={query} onInput={(e) => setQuery(e.currentTarget.value)} />
        </div>
        <Segmented value={filter} onChange={setFilter} options={[
          { value: 'all', label: `Все ${nodes.length}` },
          { value: 'online', label: `Онлайн ${counts.online}` },
          { value: 'offline', label: `Офлайн ${counts.offline}` },
          { value: 'problems', label: `Проблемы ${counts.problems}` },
          { value: 'outdated', label: `Устарели ${counts.outdated}` },
        ]} />
      </div>

      <div class="card card--flush">
        {nodes.length === 0 ? (
          <Empty icon="server" title="Нод пока нет" action={<Button variant="primary" icon="plus" onClick={() => setAdding(true)}>Добавить ноду</Button>}>
            Добавьте сервер с RemnaNode — панель выдаст команду установки агента.
          </Empty>
        ) : visible.length === 0 ? (
          <Empty icon="filter" title="Ничего не найдено">Измените фильтр или строку поиска.</Empty>
        ) : (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th class="col-check">
                    <input type="checkbox" class="checkbox" checked={allChecked} onChange={() => setSelected(allChecked ? new Set() : new Set(visible.map((n) => n.id)))} />
                  </th>
                  <th>Нода</th>
                  <th>Состояние</th>
                  <th title="Защита от торрентов">Торренты</th>
                  <th title="Защита от сканирования портов">Скан</th>
                  <th>Нагрузка</th>
                  <th>Сертификат</th>
                  <th>Агент</th>
                  <th class="col-actions" />
                </tr>
              </thead>
              <tbody>
                {visible.map((n) => {
                  const st = nodeState(n);
                  const mem = n.metrics?.mem_total ? (100 * n.metrics.mem_used) / n.metrics.mem_total : null;
                  return (
                    <tr key={n.id} class="is-clickable" onClick={() => navigate(`/nodes/${n.id}`)}>
                      <td class="col-check" onClick={(e) => e.stopPropagation()}>
                        <input type="checkbox" class="checkbox" checked={selected.has(n.id)} onChange={() => {
                          const next = new Set(selected);
                          next.has(n.id) ? next.delete(n.id) : next.add(n.id);
                          setSelected(next);
                        }} />
                      </td>
                      <td>
                        <div class="node-cell">
                          <StatusDot state={st.dot} />
                          <div class="grow">
                            <div class="node-cell__name">{n.name}</div>
                            <div class="tiny faint mono">{n.ip || '—'}</div>
                          </div>
                          {(n.tags || []).slice(0, 2).map((t: string) => <Badge size="sm" key={t}>{t}</Badge>)}
                        </div>
                      </td>
                      <td>
                        <div class="small">{st.text}</div>
                        {n.online && <div class="tiny faint">аптайм {uptime(n.metrics?.uptime)}</div>}
                        {n.problems?.length > 0 && <div class="tiny warn-text ellipsis" style={{ maxWidth: '220px' }} title={n.problems.join('\n')}>{n.problems[0]}</div>}
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <Switch on={n.torrent_enabled} disabled={n.status !== 'active'} onChange={(v) => toggleFeature(n, 'torrent_enabled', v)} label="Торренты" />
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <Switch on={n.scan_enabled} disabled={n.status !== 'active'} onChange={(v) => toggleFeature(n, 'scan_enabled', v)} label="Сканирование" />
                      </td>
                      <td style={{ minWidth: '130px' }}>
                        {n.online ? (
                          <div class="load-cell">
                            <span class="tiny faint">CPU</span><Meter value={n.metrics?.cpu} /><span class="tiny num">{Math.round(n.metrics?.cpu ?? 0)}%</span>
                            <span class="tiny faint">RAM</span><Meter value={mem} /><span class="tiny num">{Math.round(mem ?? 0)}%</span>
                          </div>
                        ) : <span class="faint">—</span>}
                      </td>
                      <td>
                        {n.cert_id ? (
                          n.cert_state?.error ? <Badge tone="bad" size="sm">ошибка</Badge> : n.cert_state?.id ? <Badge tone="ok" size="sm">v{n.cert_state.version}</Badge> : <Badge size="sm">ожидает</Badge>
                        ) : <span class="faint">—</span>}
                      </td>
                      <td>
                        <div class="row" style={{ gap: '6px' }}>
                          <span class="mono tiny">{n.agent_version || '—'}</span>
                          {n.updating ? <Badge tone="accent" size="sm">→ {n.agent_latest}</Badge> : n.update_available && <Badge tone="warn" size="sm">обновить</Badge>}
                        </div>
                      </td>
                      <td class="col-actions">
                        <Menu items={[
                          { label: 'Открыть', icon: 'arrowRight', onClick: () => navigate(`/nodes/${n.id}`) },
                          ...(n.update_available ? [{ label: `Обновить агент до ${n.agent_latest}`, icon: 'download', onClick: () => run('u', () => api.post(`/api/nodes/${n.id}/update`), 'Обновление запущено') }] : []),
                          { label: 'Диагностика', icon: 'stethoscope', onClick: () => run('d', () => api.post(`/api/nodes/${n.id}/command`, { type: 'diagnose' }), 'Диагностика запрошена') },
                          ...(n.status === 'pending' ? [{ label: 'Команда установки', icon: 'terminal', onClick: () => navigate(`/nodes/${n.id}?install=1`) }] : []),
                        ]} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected.size > 0 && (
        <div class="bulkbar">
          <b>{selected.size}</b>
          <span class="small" style={{ opacity: 0.75 }}>выбрано</span>
          <Button size="sm" variant="soft" icon="download" loading={busy === 'update_agent'} onClick={() => bulk('update_agent', undefined, 'Обновление запущено')}>Обновить агент</Button>
          <Button size="sm" variant="soft" icon="magnet" onClick={() => bulk('torrent_enabled', true, 'Торренты включены')}>Торренты вкл</Button>
          <Button size="sm" variant="soft" onClick={() => bulk('torrent_enabled', false, 'Торренты выключены')}>выкл</Button>
          <Button size="sm" variant="soft" icon="radar" onClick={() => bulk('scan_enabled', true, 'Сканирование включено')}>Скан вкл</Button>
          <Button size="sm" variant="soft" onClick={() => bulk('scan_enabled', false, 'Сканирование выключено')}>выкл</Button>
          <Button size="sm" variant="soft" icon="stethoscope" onClick={() => bulk('diagnose', undefined, 'Диагностика запрошена')}>Диагностика</Button>
          <button type="button" class="icon-btn icon-btn--sm" style={{ background: 'transparent', color: 'inherit', borderColor: 'transparent' }} onClick={() => setSelected(new Set())} title="Снять выделение">
            <Icon name="x" size={15} />
          </button>
        </div>
      )}

      {adding && <AddNodeModal onClose={() => { setAdding(false); reload(true); }} onCreated={() => reload(true)} />}
      <div class="tiny faint center">
        <Link to="/settings/protection">Общие пороги и режимы защиты</Link> применяются ко всем нодам; переключатели в таблице включают функции на конкретной ноде.
      </div>
    </div>
  );
}

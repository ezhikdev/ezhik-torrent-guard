import { useEffect, useState } from 'preact/hooks';
import { api } from '../api';
import { EventRow } from '../components/events';
import { Icon } from '../components/Icon';
import {
  Badge, Button, Callout, Empty, ErrorState, Field, Link, Loading, Menu, Modal, PageHead, Tabs, confirmDialog, useAction, useData,
} from '../components/ui';
import { REASON_LABEL, ago, dateTime, duration, until } from '../format';
import { navigate, useRoute } from '../state';

const OUTCOME: Record<string, { text: string; tone: string }> = {
  frozen: { text: 'Заморожен', tone: 'bad' },
  'blocked-permanent': { text: 'Бессрочная блокировка', tone: 'bad' },
  unfrozen: { text: 'Разморожен', tone: 'ok' },
  released: { text: 'Разблокирован вручную', tone: 'ok' },
  'already-active': { text: 'Включён вручную', tone: 'ok' },
  cancelled: { text: 'Отменено', tone: '' },
  forgotten: { text: 'Снято с учёта', tone: '' },
  skipped: { text: 'Пропущено', tone: '' },
  refused: { text: 'Отказ (сменился пользователь)', tone: 'warn' },
  failed: { text: 'Ошибка API', tone: 'bad' },
};

function ClientModal({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, error, loading } = useData(() => api.get(`/api/clients/${id}`), [id]);
  return (
    <Modal title={`Клиент #${id}`} onClose={onClose} wide>
      {loading ? <Loading /> : error ? <Callout tone="bad">{error}</Callout> : (
        <div class="stack">
          {data.remnawave ? (
            <dl class="kv">
              <dt>Пользователь</dt><dd><b>{data.remnawave.username}</b></dd>
              <dt>Статус в Remnawave</dt><dd><Badge tone={data.remnawave.status === 'ACTIVE' ? 'ok' : 'bad'} size="sm">{data.remnawave.status}</Badge></dd>
              <dt>Подписка до</dt><dd>{data.remnawave.expireAt ? new Date(data.remnawave.expireAt).toLocaleString('ru-RU') : '—'}</dd>
              {data.remnawave.telegramId && <><dt>Telegram ID</dt><dd class="mono">{data.remnawave.telegramId}</dd></>}
              {data.remnawave.description && <><dt>Описание</dt><dd>{data.remnawave.description}</dd></>}
              <dt>API Remnawave</dt><dd>{data.remnawave.api === 'v3' ? '3.x (числовой ID)' : '2.x (UUID)'}</dd>
            </dl>
          ) : (
            <Callout tone="warn">Данные Remnawave недоступны {data.remnawave_error ? `(${data.remnawave_error})` : ''}</Callout>
          )}
          {data.protected && <Callout icon="shield">Клиент в списке защищённых — блокировки к нему не применяются.</Callout>}
          {data.sanction && (
            <Callout tone="bad" icon="ban">
              {data.sanction.state === 'active'
                ? <>Заблокирован ({REASON_LABEL[data.sanction.reason] || data.sanction.reason}), разблокировка {until(data.sanction.unfreeze_at)}</>
                : <>Ожидает блокировки: {data.sanction.last_error || 'в очереди'}</>}
            </Callout>
          )}
          <div>
            <div class="eyebrow" style={{ marginBottom: '8px' }}>События ({data.events.length})</div>
            <div class="card card--flush event-list" style={{ maxHeight: '320px', overflowY: 'auto' }}>
              {data.events.length === 0 ? <div class="small faint" style={{ padding: '16px' }}>Событий нет</div> : data.events.map((e: any) => <EventRow event={e} key={e.id} />)}
            </div>
          </div>
          {data.history.length > 0 && (
            <div>
              <div class="eyebrow" style={{ marginBottom: '8px' }}>История блокировок</div>
              {data.history.slice(0, 10).map((h: any) => (
                <div class="row small" style={{ padding: '5px 0' }} key={h.id}>
                  <Badge size="sm" tone={OUTCOME[h.outcome]?.tone}>{OUTCOME[h.outcome]?.text || h.outcome}</Badge>
                  <span class="grow muted">{REASON_LABEL[h.reason] || h.reason}</span>
                  <span class="faint tiny">{dateTime(h.at)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

function BlockModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [client, setClient] = useState('');
  const [minutes, setMinutes] = useState('60');
  const { busy, run } = useAction();
  return (
    <Modal title="Заблокировать вручную" desc="Пользователь будет отключён в Remnawave и автоматически включён по истечении срока." onClose={onClose}>
      <div class="form-grid">
        <Field label="ID клиента Remnawave"><input class="input input--mono" value={client} onInput={(e) => setClient(e.currentTarget.value)} placeholder="12345" /></Field>
        <Field label="Срок, минут" hint="0 — бессрочно"><input class="input" type="number" min={0} value={minutes} onInput={(e) => setMinutes(e.currentTarget.value)} /></Field>
      </div>
      <div class="form-actions">
        <Button variant="plain" onClick={onClose}>Отмена</Button>
        <Button variant="danger" loading={busy === 'b'} disabled={!/^\d+$/.test(client)} onClick={() => run('b', async () => {
          await api.post('/api/sanctions/block', { client_id: client, seconds: Number(minutes) * 60 });
          onDone();
          onClose();
        }, 'Блокировка поставлена в очередь')}>Заблокировать</Button>
      </div>
    </Modal>
  );
}

export function Sanctions() {
  const { params } = useRoute();
  const [tab, setTab] = useState<'active' | 'history' | 'protected'>('active');
  const [client, setClient] = useState<string | null>(params.get('client'));
  const [blocking, setBlocking] = useState(false);
  const [lookup, setLookup] = useState('');
  const { data, error, loading, reload } = useData(() => api.get('/api/sanctions'), [], 10000);
  const { busy, run } = useAction();
  useEffect(() => setClient(params.get('client')), [params.get('client')]);

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  const rows: any[] = data.sanctions;
  const openClient = (id: string) => navigate(`/sanctions?client=${id}`);

  return (
    <div class="stack">
      <PageHead title="Блокировки" sub="Единый реестр санкций для всех нод: один нарушитель — одна блокировка"
        actions={
          <>
            <form class="input-group" onSubmit={(e) => { e.preventDefault(); if (/^\d+$/.test(lookup)) openClient(lookup); }}>
              <Icon name="search" size={16} />
              <input class="input" style={{ width: '200px' }} placeholder="Найти клиента по ID" value={lookup} onInput={(e) => setLookup(e.currentTarget.value)} />
            </form>
            <Button icon="ban" onClick={() => setBlocking(true)}>Заблокировать</Button>
          </>
        } />
      <Tabs value={tab} onChange={setTab} tabs={[
        { value: 'active', label: `Действующие (${rows.length})`, icon: 'ban' },
        { value: 'history', label: 'История', icon: 'clock' },
        { value: 'protected', label: `Защищённые (${data.protected_clients.length})`, icon: 'shield' },
      ]} />

      {tab === 'active' && (
        <div class="card card--flush">
          {rows.length === 0 ? <Empty icon="check" title="Активных блокировок нет">Когда защита обнаружит нарушение в режиме блокировки, пользователь появится здесь.</Empty> : (
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>Клиент</th><th>Причина</th><th>Нода</th><th>Статус</th><th>Разблокировка</th><th class="col-actions" /></tr></thead>
                <tbody>
                  {rows.map((s) => (
                    <tr key={s.client_id} class="is-clickable" onClick={() => openClient(s.client_id)}>
                      <td><div class="mono">#{s.client_id}</div><div class="tiny faint">{s.username || ''}</div></td>
                      <td>{REASON_LABEL[s.reason] || s.reason}{s.source === 'legacy-1.x' && <Badge size="sm">из 1.x</Badge>}</td>
                      <td>{s.node_name ? <Link to={`/nodes/${s.node_id}`}>{s.node_name}</Link> : '—'}</td>
                      <td>
                        {s.state === 'active' ? <Badge tone="bad" size="sm">заблокирован</Badge> : <Badge tone="warn" size="sm">в очереди</Badge>}
                        {s.hold ? <Badge size="sm">удержание</Badge> : null}
                        {s.last_error && s.state === 'pending' && <div class="tiny warn-text">{s.last_error}</div>}
                      </td>
                      <td>
                        {s.state === 'active' ? <><div class="small">{until(s.unfreeze_at)}</div><div class="tiny faint">{dateTime(s.unfreeze_at)}</div></> : <span class="faint">—</span>}
                      </td>
                      <td class="col-actions">
                        <Menu items={[
                          { label: 'Разблокировать сейчас', icon: 'play', onClick: async () => {
                            if (await confirmDialog({ title: `Разблокировать #${s.client_id}?`, text: 'Пользователь будет включён в Remnawave немедленно.', confirm: 'Разблокировать' })) {
                              run('r', async () => { await api.post(`/api/sanctions/${s.client_id}/release`); reload(true); }, 'Разблокирован');
                            }
                          } },
                          ...(s.state === 'active' ? [
                            { label: s.hold ? 'Снять удержание' : 'Удерживать (не разблокировать)', icon: 'pause', onClick: () => run('h', async () => { await api.post(`/api/sanctions/${s.client_id}/hold`, { hold: !s.hold }); reload(true); }, 'Сохранено') },
                            { label: 'Продлить на 1 час', icon: 'clock', onClick: () => run('e', async () => { await api.post(`/api/sanctions/${s.client_id}/extend`, { seconds: 3600 }); reload(true); }, 'Продлено') },
                            { label: 'Продлить на 1 сутки', icon: 'clock', onClick: () => run('e', async () => { await api.post(`/api/sanctions/${s.client_id}/extend`, { seconds: 86400 }); reload(true); }, 'Продлено') },
                          ] : []),
                          'sep',
                          { label: 'Снять с учёта (не трогать Remnawave)', icon: 'x', danger: true, onClick: async () => {
                            if (await confirmDialog({ title: 'Снять с учёта?', text: 'Панель забудет блокировку и не будет включать пользователя автоматически.', danger: true, confirm: 'Снять' })) {
                              run('f', async () => { await api.post(`/api/sanctions/${s.client_id}/forget`); reload(true); }, 'Снято с учёта');
                            }
                          } },
                        ]} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'history' && (
        <div class="card card--flush">
          {data.history.length === 0 ? <Empty icon="clock" title="История пуста" /> : (
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>Время</th><th>Клиент</th><th>Результат</th><th>Причина</th><th>Нода</th><th>Детали</th></tr></thead>
                <tbody>
                  {data.history.map((h: any) => (
                    <tr key={h.id} class="is-clickable" onClick={() => openClient(h.client_id)}>
                      <td class="small" title={dateTime(h.at)}>{ago(h.at)}</td>
                      <td class="mono">#{h.client_id}</td>
                      <td><Badge size="sm" tone={OUTCOME[h.outcome]?.tone}>{OUTCOME[h.outcome]?.text || h.outcome}</Badge></td>
                      <td>{REASON_LABEL[h.reason] || h.reason}</td>
                      <td>{h.node_name || '—'}</td>
                      <td class="tiny faint">{h.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'protected' && <ProtectedClients list={data.protected_clients} onSaved={() => reload(true)} busy={busy} />}

      {client && <ClientModal id={client} onClose={() => navigate('/sanctions', true)} />}
      {blocking && <BlockModal onClose={() => setBlocking(false)} onDone={() => reload(true)} />}
      <div class="tiny faint center">
        Сроки блокировок: <Link to="/settings/protection">Настройки → Защита</Link>. Длительность по умолчанию: торренты {duration(900)}.
      </div>
    </div>
  );
}

function ProtectedClients({ list, onSaved }: { list: string[]; onSaved: () => void; busy: string | null }) {
  const [value, setValue] = useState('');
  const { busy, run } = useAction();
  const save = (next: string[]) => run('p', async () => {
    await api.put('/api/settings/protection', { protected_clients: next });
    onSaved();
  }, 'Список обновлён');
  return (
    <div class="card">
      <p class="small muted" style={{ marginBottom: '14px' }}>
        Клиенты из этого списка никогда не блокируются: события по ним записываются с пометкой «защищённый». Подходит для служебных и тестовых аккаунтов.
      </p>
      <form class="row" onSubmit={(e) => { e.preventDefault(); const v = value.trim(); if (/^\d+$/.test(v) && !list.includes(v)) { save([...list, v]); setValue(''); } }}>
        <input class="input input--mono" style={{ maxWidth: '240px' }} placeholder="ID клиента" value={value} onInput={(e) => setValue(e.currentTarget.value)} />
        <Button type="submit" icon="plus" loading={busy === 'p'} disabled={!/^\d+$/.test(value.trim())}>Добавить</Button>
      </form>
      <div class="chips" style={{ marginTop: '14px' }}>
        {list.length === 0 && <span class="small faint">Список пуст</span>}
        {list.map((c) => (
          <span class="chip" key={c}>#{c}<button type="button" title="Убрать" onClick={() => save(list.filter((x) => x !== c))}><Icon name="x" size={12} /></button></span>
        ))}
      </div>
    </div>
  );
}

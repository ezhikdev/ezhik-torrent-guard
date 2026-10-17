import { useEffect, useState } from 'preact/hooks';
import { api } from '../api';
import { Icon } from '../components/Icon';
import {
  Badge, Button, Callout, CodeBox, Empty, ErrorState, Field, Link, Loading, Modal, PageHead, Segmented, Switch, Tabs, ToggleRow,
  confirmDialog, useAction, useData,
} from '../components/ui';
import { ago, bytes, dateTime } from '../format';
import { navigate } from '../state';
import { certStatus } from './Certificates';

type Tab = 'protection' | 'remnawave' | 'notifications' | 'certificates' | 'panel' | 'security' | 'updates' | 'audit';

const TABS: { value: Tab; label: string; icon: string }[] = [
  { value: 'protection', label: 'Защита', icon: 'shield' },
  { value: 'remnawave', label: 'Remnawave', icon: 'link' },
  { value: 'notifications', label: 'Уведомления', icon: 'telegram' },
  { value: 'certificates', label: 'ACME и DNS', icon: 'certificate' },
  { value: 'panel', label: 'Панель', icon: 'globe' },
  { value: 'security', label: 'Безопасность', icon: 'lock' },
  { value: 'updates', label: 'Обновления', icon: 'download' },
  { value: 'audit', label: 'Журнал', icon: 'doc' },
];

function NumberField({ label, hint, value, onChange, suffix, min = 0 }: { label: string; hint?: string; value: number; onChange: (v: number) => void; suffix?: string; min?: number }) {
  return (
    <Field label={label} hint={hint}>
      <div class="input-group">
        <input class="input" type="number" min={min} value={value} onInput={(e) => onChange(Number(e.currentTarget.value))} />
        {suffix && <span class="input-suffix">{suffix}</span>}
      </div>
    </Field>
  );
}

function ModeSwitch({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return <Segmented value={value} onChange={onChange} options={[{ value: 'observe', label: 'Наблюдение' }, { value: 'enforce', label: 'Блокировка' }]} />;
}

function ProtectionTab({ settings, reload }: { settings: any; reload: () => void }) {
  const [p, setP] = useState<any>(settings.protection);
  const [advanced, setAdvanced] = useState(false);
  const { busy, run } = useAction();
  const set = (section: string, key: string, value: any) => setP({ ...p, [section]: { ...p[section], [key]: value } });
  const minutes = (s: number) => Math.round(s / 60);
  const dirty = JSON.stringify(p) !== JSON.stringify(settings.protection);
  const save = () => run('save', async () => {
    setP(await api.put('/api/settings/protection', p));
    reload();
  }, 'Настройки защиты сохранены и отправлены на ноды');

  return (
    <div class="stack">
      <Callout icon="info">
        Настройки едины для всех нод и применяются мгновенно. Включение защиты на конкретной ноде — переключатели на странице «Ноды».
        В режиме <b>наблюдения</b> нарушения только записываются; в режиме <b>блокировки</b> пользователь отключается в Remnawave.
      </Callout>

      <div class="card">
        <div class="settings-section">
          <div class="settings-section__head">
            <span class="stat__icon"><Icon name="magnet" size={18} /></span>
            <div class="grow">
              <div class="card-title">Торренты (точная атрибуция nDPI)</div>
              <div class="small muted">Первый BitTorrent-сокет, однозначно связанный с клиентом Xray, — основание для заморозки.</div>
            </div>
            <ModeSwitch value={p.torrent.mode} onChange={(v) => set('torrent', 'mode', v)} />
          </div>
          <div class="form-grid">
            <NumberField label="Длительность заморозки" suffix="мин" min={1} value={minutes(p.torrent.freeze_seconds)} onChange={(v) => set('torrent', 'freeze_seconds', v * 60)} />
            <Field label="Для новых нод"><div class="row"><Switch on={p.torrent.default_enabled} onChange={(v) => set('torrent', 'default_enabled', v)} /><span class="small muted">включать по умолчанию</span></div></Field>
          </div>
        </div>

        <div class="settings-section">
          <div class="settings-section__head">
            <span class="stat__icon"><Icon name="network" size={18} /></span>
            <div class="grow">
              <div class="card-title">P2P / DHT fan-out</div>
              <div class="small muted">Сотни разных хостов на случайных портах за минуту — шифрованный торрент, DHT, uTP. Именно это провайдеры присылают как «portscan». Работает на нодах с включённой защитой от торрентов.</div>
            </div>
            <Switch on={p.p2p.enabled} onChange={(v) => set('p2p', 'enabled', v)} />
          </div>
          {p.p2p.enabled && (
            <div class="form-grid">
              <Field label="Режим"><ModeSwitch value={p.p2p.mode} onChange={(v) => set('p2p', 'mode', v)} /></Field>
              <NumberField label="Длительность блокировки" suffix="мин" min={1} value={minutes(p.p2p.block_seconds)} onChange={(v) => set('p2p', 'block_seconds', v * 60)} />
              {advanced && <>
                <NumberField label="UDP: уникальных хостов" hint="за окно наблюдения" value={p.p2p.udp_hosts} onChange={(v) => set('p2p', 'udp_hosts', v)} />
                <NumberField label="UDP: разных сетей /16" value={p.p2p.udp_networks} onChange={(v) => set('p2p', 'udp_networks', v)} />
                <NumberField label="TCP: уникальных хостов" value={p.p2p.tcp_hosts} onChange={(v) => set('p2p', 'tcp_hosts', v)} />
                <NumberField label="TCP: разных сетей /16" value={p.p2p.tcp_networks} onChange={(v) => set('p2p', 'tcp_networks', v)} />
              </>}
            </div>
          )}
        </div>

        <div class="settings-section">
          <div class="settings-section__head">
            <span class="stat__icon"><Icon name="radar" size={18} /></span>
            <div class="grow">
              <div class="card-title">Сканирование портов</div>
              <div class="small muted">Перебор портов одного IP и плотное сканирование подсети /24 конкретным клиентом.</div>
            </div>
            <ModeSwitch value={p.scan.mode} onChange={(v) => set('scan', 'mode', v)} />
          </div>
          <div class="form-grid">
            <NumberField label="Длительность блокировки" suffix="мин" hint="0 — бессрочно (снять вручную в Remnawave)" value={minutes(p.scan.block_seconds)} onChange={(v) => set('scan', 'block_seconds', v * 60)} />
            <Field label="Для новых нод"><div class="row"><Switch on={p.scan.default_enabled} onChange={(v) => set('scan', 'default_enabled', v)} /><span class="small muted">включать по умолчанию</span></div></Field>
            {advanced && <>
              <NumberField label="Окно наблюдения" suffix="с" value={p.scan.window_seconds} onChange={(v) => set('scan', 'window_seconds', v)} />
              <NumberField label="Повтор отчёта не чаще" suffix="с" value={p.scan.cooldown_seconds} onChange={(v) => set('scan', 'cooldown_seconds', v)} />
              <NumberField label="TCP: портов одного IP" value={p.scan.tcp_vertical_ports} onChange={(v) => set('scan', 'tcp_vertical_ports', v)} />
              <NumberField label="UDP: портов одного IP" value={p.scan.udp_vertical_ports} onChange={(v) => set('scan', 'udp_vertical_ports', v)} />
              <NumberField label="Подсеть /24: хостов" value={p.scan.subnet_hosts} onChange={(v) => set('scan', 'subnet_hosts', v)} />
              <NumberField label="Подсеть /24: портов" value={p.scan.subnet_ports} onChange={(v) => set('scan', 'subnet_ports', v)} />
              <NumberField label="Подсеть /24: назначений" value={p.scan.subnet_endpoints} onChange={(v) => set('scan', 'subnet_endpoints', v)} />
            </>}
          </div>
        </div>

        {advanced && (
          <div class="settings-section">
            <div class="settings-section__head"><span class="stat__icon"><Icon name="settings" size={18} /></span><div class="grow"><div class="card-title">Общее</div></div></div>
            <div class="form-grid">
              <NumberField label="Лимит RAM-логов" suffix="МБ" min={1} value={Math.round(p.log_max_bytes / 1048576)} onChange={(v) => setP({ ...p, log_max_bytes: v * 1048576 })} />
              <NumberField label="Не блокировать события старше" suffix="мин" value={Math.round(p.max_event_age_seconds / 60)} onChange={(v) => setP({ ...p, max_event_age_seconds: v * 60 })} />
              <Field label="Старые версии на нодах"><div class="row"><Switch on={p.remove_legacy} onChange={(v) => setP({ ...p, remove_legacy: v })} /><span class="small muted">удалять Torrent Guard 1.x автоматически</span></div></Field>
            </div>
          </div>
        )}

        <div class="form-actions">
          <Button variant="plain" icon={advanced ? 'minus' : 'plus'} onClick={() => setAdvanced(!advanced)}>{advanced ? 'Скрыть пороги' : 'Пороги и тонкая настройка'}</Button>
          <Button variant="primary" loading={busy === 'save'} disabled={!dirty} onClick={save}>Сохранить</Button>
        </div>
      </div>
    </div>
  );
}

function RemnawaveTab({ settings, reload }: { settings: any; reload: () => void }) {
  const [url, setUrl] = useState(settings.remnawave.url || '');
  const [token, setToken] = useState('');
  const [result, setResult] = useState<any>(null);
  const { busy, run } = useAction();
  return (
    <div class="card">
      <div class="stack">
        <p class="small muted">
          Панель отключает и включает пользователей через API Remnawave. Поддерживаются <b>3.x</b> (числовые ID, текущая 3.4.4) и <b>2.x</b>:
          версия определяется автоматически и перепроверяется после обновления Remnawave. Ноды могут оставаться на старой версии RemnaNode — ID клиента в логах Xray не изменился.
        </p>
        <div class="form-grid">
          <Field label="Адрес панели Remnawave"><input class="input" value={url} placeholder="https://panel.example.com" onInput={(e) => setUrl(e.currentTarget.value)} /></Field>
          <Field label="API-токен" hint={settings.remnawave.token_set ? `Сохранён ${settings.remnawave.token_hint}. Оставьте пустым, чтобы не менять.` : 'Remnawave → API Tokens. Нужны права на чтение и действия с пользователями.'}>
            <input class="input input--mono" type="password" value={token} placeholder={settings.remnawave.token_set ? '••••••••' : 'eyJhbGciOi…'} onInput={(e) => setToken(e.currentTarget.value)} />
          </Field>
        </div>
        {result && (result.ok ? (
          <Callout tone="ok">Подключение успешно · API {result.api === 'v3' ? '3.x' : '2.x'}{result.panel_version ? ` · Remnawave ${result.panel_version}` : ''}</Callout>
        ) : <Callout tone="bad">{result.error}</Callout>)}
        <div class="form-actions">
          <Button icon="zap" loading={busy === 'test'} disabled={!url} onClick={() => run('test', async () => setResult(await api.post('/api/settings/remnawave/test', { url, token: token || undefined })))}>Проверить</Button>
          <Button variant="primary" loading={busy === 'save'} disabled={!url} onClick={() => run('save', async () => {
            await api.put('/api/settings/remnawave', { url, token: token || undefined });
            setToken('');
            reload();
            setResult(await api.post('/api/settings/remnawave/test', {}));
          }, 'Сохранено')}>Сохранить</Button>
        </div>
      </div>
    </div>
  );
}

function NotificationsTab({ settings, reload }: { settings: any; reload: () => void }) {
  const tg = settings.telegram;
  const [enabled, setEnabled] = useState(!!tg.enabled);
  const [chat, setChat] = useState(tg.chat_id || '');
  const [token, setToken] = useState('');
  const [notify, setNotify] = useState<any>(tg.notify);
  const { busy, run } = useAction();
  const items = [
    ['torrent', 'Торренты', 'Каждое обнаружение BitTorrent'],
    ['p2p', 'P2P / DHT', 'С отчётом-файлом по назначениям'],
    ['scan', 'Сканирование портов', 'С отчётом-файлом для ответа хостеру'],
    ['nodes', 'Ноды', 'Недоступность, восстановление, обновления'],
    ['certs', 'Сертификаты', 'Выпуск, ошибки, истечение, нужны DNS-записи'],
    ['sanctions', 'Ошибки блокировок', 'Не удалось отключить пользователя в Remnawave'],
  ];
  return (
    <div class="card">
      <ToggleRow title="Уведомления в Telegram" desc="Бот присылает события в личный чат или группу" on={enabled} onChange={setEnabled} />
      <div class="form-grid" style={{ margin: '8px 0 14px' }}>
        <Field label="Токен бота" hint={tg.token_set ? 'Сохранён. Оставьте пустым, чтобы не менять.' : 'Получите у @BotFather'}>
          <input class="input input--mono" type="password" value={token} placeholder={tg.token_set ? '••••••••' : '123456:ABC…'} onInput={(e) => setToken(e.currentTarget.value)} />
        </Field>
        <Field label="Chat ID" hint="Число; для групп начинается с -100"><input class="input input--mono" value={chat} onInput={(e) => setChat(e.currentTarget.value)} /></Field>
      </div>
      <div class="eyebrow" style={{ margin: '6px 0' }}>О чём сообщать</div>
      {items.map(([key, title, desc]) => (
        <ToggleRow key={key} title={title} desc={desc} on={!!notify[key]} onChange={(v) => setNotify({ ...notify, [key]: v })} />
      ))}
      <div class="form-actions">
        <Button icon="send" loading={busy === 'test'} onClick={() => run('test', () => api.post('/api/settings/telegram/test', { token: token || undefined, chat_id: chat || undefined }), 'Тестовое сообщение отправлено')}>Тест</Button>
        <Button variant="primary" loading={busy === 'save'} onClick={() => run('save', async () => {
          await api.put('/api/settings/telegram', { enabled, chat_id: chat, token: token || undefined, notify });
          setToken('');
          reload();
        }, 'Сохранено')}>Сохранить</Button>
      </div>
    </div>
  );
}

function ProviderModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [type, setType] = useState<'cloudflare' | 'acmedns'>('cloudflare');
  const [name, setName] = useState('');
  const [token, setToken] = useState('');
  const [server, setServer] = useState('https://auth.acme-dns.io');
  const [created, setCreated] = useState<any>(null);
  const { busy, run } = useAction();
  if (created) {
    return (
      <Modal title="acme-dns подключён" onClose={() => { onDone(); onClose(); }}>
        <div class="stack">
          <p class="small muted">Один раз создайте CNAME у DNS-хостинга для каждого имени проверки, которое будете выпускать через этот провайдер:</p>
          <CodeBox text={`_acme-challenge.example.com  CNAME  ${created.fulldomain}`} />
          <p class="tiny faint">Для wildcard *.sub.example.com имя проверки — _acme-challenge.sub.example.com. После этого выпуск и продление полностью автоматические.</p>
          <div class="form-actions"><Button variant="primary" onClick={() => { onDone(); onClose(); }}>Готово</Button></div>
        </div>
      </Modal>
    );
  }
  return (
    <Modal title="DNS-провайдер" desc="Для автоматической проверки DNS-01 и продления сертификатов" onClose={onClose}>
      <div class="stack">
        <Segmented value={type} onChange={setType} options={[{ value: 'cloudflare', label: 'Cloudflare' }, { value: 'acmedns', label: 'acme-dns (любой DNS)' }]} />
        <Field label="Название"><input class="input" value={name} placeholder={type === 'cloudflare' ? 'Cloudflare' : 'acme-dns'} onInput={(e) => setName(e.currentTarget.value)} /></Field>
        {type === 'cloudflare' ? (
          <Field label="API-токен Cloudflare" hint="My Profile → API Tokens → шаблон «Edit zone DNS» для нужных зон">
            <input class="input input--mono" type="password" value={token} onInput={(e) => setToken(e.currentTarget.value)} />
          </Field>
        ) : (
          <Field label="Сервер acme-dns" hint="Публичный auth.acme-dns.io или свой сервер">
            <input class="input input--mono" value={server} onInput={(e) => setServer(e.currentTarget.value)} />
          </Field>
        )}
        <div class="form-actions">
          <Button variant="plain" onClick={onClose}>Отмена</Button>
          <Button variant="primary" loading={busy === 'c'} disabled={type === 'cloudflare' && !token} onClick={() => run('c', async () => {
            const r = await api.post('/api/dns-providers', { type, name: name || (type === 'cloudflare' ? 'Cloudflare' : 'acme-dns'), token, server });
            if (type === 'acmedns') setCreated(r);
            else { onDone(); onClose(); }
          }, 'Провайдер добавлен')}>Подключить</Button>
        </div>
      </div>
    </Modal>
  );
}

function CertificatesTab({ settings, reload }: { settings: any; reload: () => void }) {
  const { data, reload: reloadProviders } = useData(() => api.get('/api/certificates'), []);
  const [acme, setAcme] = useState<any>(settings.acme);
  const [adding, setAdding] = useState(false);
  const { busy, run } = useAction();
  const staging = acme.directory.includes('staging');
  return (
    <div class="stack">
      <div class="card">
        <div class="card-title" style={{ marginBottom: '14px' }}>Let's Encrypt (ACME)</div>
        <div class="form-grid">
          <Field label="E-mail аккаунта"><input class="input" type="email" value={acme.email} onInput={(e) => setAcme({ ...acme, email: e.currentTarget.value })} /></Field>
          <NumberField label="Продлевать за" suffix="дней" value={acme.renew_days} onChange={(v) => setAcme({ ...acme, renew_days: v })} />
          <Field label="Сервер ACME">
            <select class="select" value={staging ? 'staging' : acme.directory.includes('letsencrypt.org') ? 'prod' : 'custom'} onChange={(e) => {
              const v = e.currentTarget.value;
              if (v === 'prod') setAcme({ ...acme, directory: 'https://acme-v02.api.letsencrypt.org/directory' });
              if (v === 'staging') setAcme({ ...acme, directory: 'https://acme-staging-v02.api.letsencrypt.org/directory' });
            }}>
              <option value="prod">Let's Encrypt (боевой)</option>
              <option value="staging">Let's Encrypt Staging (тест, недоверенные)</option>
              <option value="custom" disabled>Другой</option>
            </select>
          </Field>
          <Field label="URL каталога"><input class="input input--mono" value={acme.directory} onInput={(e) => setAcme({ ...acme, directory: e.currentTarget.value })} /></Field>
        </div>
        <div class="form-actions">
          <Button variant="primary" loading={busy === 'acme'} onClick={() => run('acme', async () => { await api.put('/api/settings/acme', acme); reload(); }, 'Сохранено')}>Сохранить</Button>
        </div>
      </div>
      <div class="card card--flush">
        <div class="card-head" style={{ padding: '18px 20px 6px' }}>
          <div class="card-title">DNS-провайдеры</div>
          <Button size="sm" icon="plus" onClick={() => setAdding(true)}>Добавить</Button>
        </div>
        {!data?.providers?.length ? (
          <Empty icon="globe" title="Провайдеры не подключены">Без провайдера TXT-записи публикуются вручную, а продление требует ваших действий.</Empty>
        ) : (
          <table class="table">
            <thead><tr><th>Название</th><th>Тип</th><th>Детали</th><th class="col-actions" /></tr></thead>
            <tbody>
              {data.providers.map((p: any) => (
                <tr key={p.id}>
                  <td>{p.name}</td>
                  <td><Badge size="sm">{p.type === 'cloudflare' ? 'Cloudflare' : 'acme-dns'}</Badge></td>
                  <td class="mono tiny">{p.type === 'acmedns' ? `CNAME → ${p.fulldomain}` : `токен ${p.token_hint}`}</td>
                  <td class="col-actions">
                    <button type="button" class="icon-btn icon-btn--sm icon-btn--danger" title="Удалить" onClick={async () => {
                      if (await confirmDialog({ title: `Удалить ${p.name}?`, danger: true, confirm: 'Удалить' })) run('d', async () => { await api.del(`/api/dns-providers/${p.id}`); reloadProviders(); }, 'Удалён');
                    }}><Icon name="trash" size={15} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {adding && <ProviderModal onClose={() => setAdding(false)} onDone={reloadProviders} />}
    </div>
  );
}

function PanelTab({ settings, reload }: { settings: any; reload: () => void }) {
  const [host, setHost] = useState(settings.panel.public_host || '');
  const [cert, setCert] = useState(settings.panel.web_cert_id || '');
  const { data } = useData(() => api.get('/api/certificates'), []);
  const { busy, run } = useAction();
  return (
    <div class="stack">
    <DomainCard />
    <div class="card">
      <div class="stack">
        <div class="form-grid">
          <Field label="Адрес панели для нод" hint={`Используется в командах установки: ${settings.panel.agent_url}`}>
            <input class="input input--mono" value={host} placeholder="203.0.113.10 или panel.example.com" onInput={(e) => setHost(e.currentTarget.value)} />
          </Field>
          <Field label="Сертификат веб-интерфейса" hint="По умолчанию — сертификат собственного CA панели (браузер предупредит)">
            <select class="select" value={cert} onChange={(e) => setCert(e.currentTarget.value)}>
              <option value="">Собственный (самоподписанный)</option>
              {(data?.certificates || []).filter((c: any) => c.version).map((c: any) => <option value={c.id} key={c.id}>{c.name}</option>)}
            </select>
          </Field>
        </div>
        <dl class="kv">
          <dt>Веб-интерфейс</dt><dd class="mono">порт {settings.panel.web_port}</dd>
          <dt>API агентов</dt><dd class="mono">порт {settings.panel.agent_port} · канал защищён собственным CA панели</dd>
        </dl>
        <Callout icon="info">Сертификат для веб-интерфейса применяется сразу, без перезапуска. Агенты продолжают проверять панель по её CA, поэтому смена не влияет на ноды.</Callout>
        <div class="form-actions">
          <Button variant="primary" loading={busy === 's'} onClick={() => run('s', async () => { await api.put('/api/settings/panel', { public_host: host, web_cert_id: cert || null }); reload(); }, 'Сохранено')}>Сохранить</Button>
        </div>
      </div>
    </div>
    </div>
  );
}

function Check({ ok, children }: { ok: boolean | null | undefined; children: any }) {
  return (
    <div class="row small" style={{ gap: '8px' }}>
      <Icon name={ok ? 'check' : ok === false ? 'x' : 'clock'} size={15} />
      <span class={ok ? '' : ok === false ? 'bad-text' : 'faint'}>{children}</span>
    </div>
  );
}

function DomainCard() {
  const { data, reload } = useData(() => api.get('/api/system/domain'), [], 5000);
  const { data: certs } = useData(() => api.get('/api/certificates'), []);
  const [domain, setDomain] = useState('');
  const [email, setEmail] = useState('');
  const [challenge, setChallenge] = useState('http01');
  const [listen443, setListen443] = useState(true);
  const [redirect, setRedirect] = useState(true);
  const [agents, setAgents] = useState(false);
  const [check, setCheck] = useState<any>(null);
  const { busy, run } = useAction();
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    if (!data || loaded) return;
    setLoaded(true);
    if (!data.domain) return;
    setDomain(data.domain);
    setListen443(!!data.https_port);
    setRedirect(!!data.http_port);
    if (data.certificate?.provider_id) setChallenge(data.certificate.provider_id);
  }, [data]);
  if (!data) return <div class="card"><Loading /></div>;
  const cert = data.certificate;
  const st = cert ? certStatus(cert) : null;
  const providers: any[] = certs?.providers || [];
  const doCheck = () => run('check', async () => setCheck(await api.post('/api/system/domain/check', { domain })));
  const apply = () => run('apply', async () => {
    await api.post('/api/system/domain/apply', { domain, email, challenge, listen_443: listen443, redirect_http: redirect, agents_use_domain: agents });
    reload(true);
  }, 'Выпуск сертификата запущен');
  const base = `https://${data.domain}${data.https_port === 443 ? '' : `:${data.web_port}`}`;
  return (
    <div class="card">
      <div class="card-head">
        <div class="card-title row" style={{ gap: '8px' }}><Icon name="lock" size={17} /> Домен и HTTPS панели</div>
        {data.active ? <Badge tone="ok" size="sm">HTTPS по домену активен</Badge> : data.domain ? <Badge tone="warn" size="sm">настраивается</Badge> : <Badge size="sm">по IP</Badge>}
      </div>
      <div class="stack">
        {data.domain && (
          <dl class="kv">
            <dt>Домен</dt><dd class="mono">{data.domain}</dd>
            <dt>Сертификат</dt><dd>{cert ? <><Badge tone={st!.tone as any} size="sm">{st!.text}</Badge> {cert.not_after && <span class="tiny faint">до {dateTime(cert.not_after)}</span>} <Link to={`/certificates/${cert.id}`} class="tiny">подробнее</Link></> : '—'}</dd>
            <dt>Порты</dt><dd class="mono small">{data.web_port} (всегда){data.https_port ? ' · 443' : ''}{data.http_port ? ' · 80 → 301' : ''}
              {Object.entries(data.listeners?.errors || {}).map(([p, e]) => <div class="bad-text tiny" key={p}>порт {p}: {String(e)}</div>)}</dd>
            {data.active && <><dt>Адрес</dt><dd><a class="mono small" href={base} target="_blank" rel="noopener">{base}</a></dd></>}
          </dl>
        )}
        {cert?.last_error && !cert.running && <Callout tone="bad">{cert.last_error}</Callout>}
        {data.domain && cert?.provider_id === 'http01' && !data.http_port && <Callout tone="warn">Сертификат выпускается через HTTP-01, но порт 80 панели выключен — автоматическое продление не пройдёт. Включите редирект HTTP или выберите DNS-провайдера.</Callout>}
        <Field label="Домен панели" hint="A/AAAA-записи домена должны указывать на этот сервер">
          <div class="row">
            <input class="input input--mono grow" value={domain} placeholder="panel.example.com" onInput={(e) => { setDomain(e.currentTarget.value); setCheck(null); }} />
            <Button loading={busy === 'check'} disabled={!domain.trim()} onClick={doCheck}>Проверить</Button>
          </div>
        </Field>
        {check && (
          <div class="stack" style={{ gap: '4px' }}>
            <Check ok={check.dns_ok}>DNS: A {check.a.join(', ') || '—'}{check.aaaa.length ? ` · AAAA ${check.aaaa.join(', ')}` : ''} · адреса сервера {check.server.join(', ')}{check.dns_partial ? ' — указывают не все записи' : ''}</Check>
            <Check ok={check.http?.ok ?? null}>HTTP (порт 80): {check.http ? (check.http.ok ? 'доступен' : check.http.error || `код ${check.http.status}`) : 'порт 80 панели ещё не включён — проверится при выпуске'}</Check>
            <Check ok={check.https?.ok ?? null}>HTTPS: {check.https ? (check.https.ok ? 'доверенный сертификат' : 'пока нет доверенного сертификата') : '—'}</Check>
          </div>
        )}
        <div class="form-grid">
          <Field label="Проверка Let's Encrypt">
            <select class="select" value={challenge} onChange={(e) => setChallenge(e.currentTarget.value)}>
              <option value="http01">HTTP-01 (порт 80 этого сервера)</option>
              {providers.map((p) => <option value={p.id} key={p.id}>DNS-01: {p.name}</option>)}
            </select>
          </Field>
          {!data.acme_email && <Field label="E-mail для Let's Encrypt"><input class="input" type="email" value={email} onInput={(e) => setEmail(e.currentTarget.value)} /></Field>}
        </div>
        <ToggleRow title="Слушать стандартный порт 443" desc={`Панель будет открываться как https://домен/. Порт ${data.web_port} продолжит работать.`} on={listen443} onChange={setListen443} />
        <ToggleRow title="Порт 80: редирект на HTTPS" desc="Нужен для HTTP-01 и его продления" on={redirect || challenge === 'http01'} onChange={setRedirect} />
        <ToggleRow title="Агенты подключаются по домену" desc="Новые команды установки будут использовать домен. Работающие агенты продолжают по старому адресу — канал защищён CA панели." on={agents} onChange={setAgents} />
        <Callout icon="info">Переход безопасен: доступ по IP и порту {data.web_port} сохраняется, интерфейс переключится на новый сертификат только после успешного выпуска. Если на этом же сервере стоит нода с Nginx Frontend, порт 80 занят Nginx — используйте DNS-01.</Callout>
        <div class="form-actions">
          {data.domain && <Button variant="plain" loading={busy === 'reset'} onClick={async () => {
            if (await confirmDialog({ title: 'Вернуться к доступу по IP?', text: 'Порты 80/443 панели будут закрыты, интерфейс вернётся к собственному сертификату.', confirm: 'Сбросить', danger: true })) run('reset', async () => { await api.post('/api/system/domain/reset'); setDomain(''); reload(true); }, 'Домен отключён');
          }}>Отключить домен</Button>}
          <Button variant="primary" loading={busy === 'apply' || cert?.running} disabled={!domain.trim() || (!data.acme_email && !email.trim())} onClick={apply}>
            {data.domain ? 'Применить и перевыпустить' : 'Подключить домен'}
          </Button>
        </div>
      </div>
    </div>
  );
}

function SecurityTab() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const { data: sessions, reload } = useData(() => api.get('/api/auth/sessions'), []);
  const { busy, run } = useAction();
  return (
    <div class="grid grid--2">
      <div class="card">
        <div class="card-title" style={{ marginBottom: '14px' }}>Смена пароля</div>
        <div class="stack">
          <Field label="Текущий пароль"><input class="input" type="password" autoComplete="current-password" value={current} onInput={(e) => setCurrent(e.currentTarget.value)} /></Field>
          <Field label="Новый пароль" hint="Не менее 10 символов. Другие сессии будут завершены."><input class="input" type="password" autoComplete="new-password" value={next} onInput={(e) => setNext(e.currentTarget.value)} /></Field>
          <div class="form-actions">
            <Button variant="primary" loading={busy === 'p'} disabled={!current || next.length < 10} onClick={() => run('p', async () => {
              await api.post('/api/auth/password', { current, new: next });
              setCurrent('');
              setNext('');
              reload();
            }, 'Пароль изменён')}>Изменить</Button>
          </div>
        </div>
      </div>
      <div class="card card--flush">
        <div class="card-head" style={{ padding: '18px 20px 6px' }}><div class="card-title">Активные сессии</div></div>
        <div class="event-list">
          {(sessions || []).map((s: any) => (
            <div class="session-row" key={s.id}>
              <Icon name="laptop" size={18} />
              <div class="grow">
                <div class="small ellipsis">{s.user_agent || 'неизвестный клиент'}</div>
                <div class="tiny faint">{s.ip} · {ago(s.last_seen_at)} {s.current && '· текущая'}</div>
              </div>
              {!s.current && <button type="button" class="icon-btn icon-btn--sm icon-btn--danger" title="Завершить" onClick={() => run('x', async () => { await api.del(`/api/auth/sessions/${s.id}`); reload(); })}><Icon name="x" size={15} /></button>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function UpdatesTab() {
  const { data, reload } = useData(() => api.get('/api/system'), [], 5000);
  const { busy, run } = useAction();
  if (!data) return <Loading />;
  const status = data.update_status;
  const updating = status && ['requested', 'running'].includes(status.state) && Date.now() / 1000 - (status.at || status.requested_at || 0) < 900;
  return (
    <div class="grid grid--2">
      <div class="card">
        <div class="card-title" style={{ marginBottom: '14px' }}>Панель</div>
        <dl class="kv">
          <dt>Версия панели</dt><dd class="mono">{data.version}</dd>
          <dt>Версия агента</dt><dd class="mono">{data.agent_version}</dd>
          <dt>Последний релиз</dt><dd class="mono">{data.latest?.version || 'не проверялось'}</dd>
          <dt>Запущена</dt><dd>{ago(data.started_at)}</dd>
          <dt>База данных</dt><dd>{bytes(data.db_size)}</dd>
          <dt>Runtime</dt><dd class="mono tiny">{data.engine.engine_id} · Ubuntu {Object.keys(data.runtimes).join(', ')}</dd>
          <dt>CA панели</dt><dd class="mono tiny">{data.ca_fingerprint.slice(0, 32)}…</dd>
        </dl>
        {status?.state === 'failed' && <div style={{ marginTop: '14px' }}><Callout tone="bad">Обновление не удалось: {status.message}</Callout></div>}
        {status?.state === 'done' && <div style={{ marginTop: '14px' }}><Callout tone="ok">{status.message}</Callout></div>}
        <div class="form-actions">
          <Button icon="refresh" loading={busy === 'c'} onClick={() => run('c', async () => { await api.post('/api/system/check-updates'); reload(); })}>Проверить</Button>
          <Button variant="primary" icon="download" loading={busy === 'u' || updating} disabled={!data.update_available || updating} onClick={async () => {
            if (await confirmDialog({ title: `Обновить панель до ${data.latest.version}?`, text: 'Панель скачает релиз, проверит контрольную сумму и перезапустится (около минуты). При ошибке будет возвращена текущая версия. Ноды продолжают работать.', confirm: 'Обновить' })) {
              run('u', async () => { await api.post('/api/system/update'); reload(); }, 'Обновление запущено');
            }
          }}>{updating ? 'Обновляется…' : 'Обновить панель'}</Button>
        </div>
      </div>
      <div class="card">
        <div class="card-title" style={{ marginBottom: '10px' }}>Как обновляются компоненты</div>
        <div class="steps">
          <div class="step"><span class="step__num">1</span><div class="step__body small">Панель обновляется кнопкой слева или той же командой, что и при установке — она всегда ставит последний релиз.</div></div>
          <div class="step"><span class="step__num">2</span><div class="step__body small">Новая панель содержит новую версию агента. На странице «Ноды» появится «Обновить все» — ноды скачают агент с панели, проверят SHA-256 и перезапустятся.</div></div>
          <div class="step"><span class="step__num">3</span><div class="step__body small">Если новый агент не запустится, нода автоматически вернётся к предыдущей версии и сообщит об этом.</div></div>
        </div>
        {data.latest?.notes && <details style={{ marginTop: '10px' }}><summary class="small">Что нового в {data.latest.version}</summary><pre class="release-notes">{data.latest.notes}</pre></details>}
      </div>
    </div>
  );
}

function AuditTab() {
  const { data, error, reload } = useData(() => api.get('/api/system/audit?limit=300'), []);
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return <Loading />;
  return (
    <div class="card card--flush">
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Время</th><th>Кто</th><th>Действие</th><th>Объект</th></tr></thead>
          <tbody>
            {data.map((r: any) => (
              <tr key={r.id}>
                <td class="small" title={dateTime(r.at)}>{dateTime(r.at)}</td>
                <td>{r.actor}</td>
                <td class="mono tiny">{r.action}</td>
                <td class="mono tiny faint">{r.target || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function Settings({ tab }: { tab?: string }) {
  const current = (TABS.find((t) => t.value === tab)?.value || 'protection') as Tab;
  const { data, error, loading, reload } = useData(() => api.get('/api/settings'), []);
  const [key, setKey] = useState(0);
  useEffect(() => setKey((k) => k + 1), [data]);
  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  const props = { settings: data, reload: () => reload(true) };
  return (
    <div>
      <PageHead title="Настройки" sub="Единые параметры защиты, интеграции и сама панель" />
      <Tabs value={current} tabs={TABS} onChange={(v) => navigate(`/settings/${v}`)} />
      <div key={current + key}>
        {current === 'protection' && <ProtectionTab {...props} />}
        {current === 'remnawave' && <RemnawaveTab {...props} />}
        {current === 'notifications' && <NotificationsTab {...props} />}
        {current === 'certificates' && <CertificatesTab {...props} />}
        {current === 'panel' && <PanelTab {...props} />}
        {current === 'security' && <SecurityTab />}
        {current === 'updates' && <UpdatesTab />}
        {current === 'audit' && <AuditTab />}
      </div>
    </div>
  );
}

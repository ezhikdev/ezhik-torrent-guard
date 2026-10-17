import { useEffect, useState } from 'preact/hooks';
import { api } from '../api';
import { Icon } from '../components/Icon';
import {
  Badge, Button, Callout, Empty, ErrorState, Field, Link, Loading, Modal, PageHead, Segmented, Switch, useAction, useData,
} from '../components/ui';
import { dateShort, daysLeft, pl } from '../format';
import { navigate } from '../state';

export function certStatus(c: any): { tone: string; text: string } {
  if (c.running) return { tone: 'accent', text: 'выпускается…' };
  if (c.status === 'pending_dns') return { tone: 'warn', text: 'нужны DNS-записи' };
  if (c.status === 'failed') return { tone: 'bad', text: 'ошибка' };
  if (c.status === 'new') return { tone: 'accent', text: 'в очереди' };
  const left = daysLeft(c.not_after);
  if (left != null && left < 0) return { tone: 'bad', text: 'истёк' };
  if (left != null && left < 21) return { tone: 'warn', text: `истекает через ${pl(left, ['день', 'дня', 'дней'])}` };
  return { tone: 'ok', text: 'действует' };
}

export function ValidityBar({ from, to }: { from?: number; to?: number }) {
  if (!from || !to) return null;
  const now = Date.now() / 1000;
  const pct = Math.max(0, Math.min(100, ((now - from) / (to - from)) * 100));
  const left = daysLeft(to) ?? 0;
  return (
    <div class="meter" title={`${dateShort(from)} — ${dateShort(to)}`}>
      <div class={`meter__fill ${left < 7 ? 'meter__fill--bad' : left < 21 ? 'meter__fill--warn' : ''}`} style={{ width: `${100 - pct}%` }} />
    </div>
  );
}

function DomainInput({ domains, setDomains }: { domains: string[]; setDomains: (d: string[]) => void }) {
  const [value, setValue] = useState('');
  const [hints, setHints] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!domains.length) {
      setHints([]);
      return;
    }
    const t = setTimeout(async () => {
      try {
        const r = await api.post('/api/certificates/analyze', { domains });
        setHints(r.hints);
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }, 250);
    return () => clearTimeout(t);
  }, [domains.join(',')]);

  const add = (raw: string) => {
    const parts = raw.split(/[\s,;]+/).map((p) => p.trim().toLowerCase()).filter(Boolean);
    const next = [...domains];
    for (const p of parts) if (!next.includes(p)) next.push(p);
    setDomains(next);
    setValue('');
  };

  return (
    <div class="stack stack--sm">
      <div class="domain-input">
        {domains.map((d) => (
          <span class="chip" key={d}>{d}<button type="button" onClick={() => setDomains(domains.filter((x) => x !== d))}><Icon name="x" size={12} /></button></span>
        ))}
        <input
          class="domain-input__field"
          placeholder={domains.length ? 'ещё домен…' : '*.example.com, example.com'}
          value={value}
          onInput={(e) => setValue(e.currentTarget.value)}
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ',' || e.key === ' ') && value.trim()) {
              e.preventDefault();
              add(value);
            } else if (e.key === 'Backspace' && !value && domains.length) {
              setDomains(domains.slice(0, -1));
            }
          }}
          onBlur={() => value.trim() && add(value)}
        />
      </div>
      {error && <div class="field__error">{error}</div>}
      {hints.map((h, i) => (
        <div class="hint-row" key={i}>
          <Icon name="info" size={14} />
          <span class="grow">{h.text}</span>
          {h.suggest && !domains.includes(h.suggest) && <Button size="sm" variant="soft" icon="plus" onClick={() => add(h.suggest)}>{h.suggest}</Button>}
        </div>
      ))}
    </div>
  );
}

export function NewCertificateModal({ onClose, data, onCreated }: { onClose: () => void; data: any; onCreated: () => void }) {
  const [mode, setMode] = useState<'acme' | 'upload'>('acme');
  const [name, setName] = useState('');
  const [domains, setDomains] = useState<string[]>([]);
  const [provider, setProvider] = useState(data.providers[0]?.id || '');
  const [keyType, setKeyType] = useState('ec256');
  const [autoRenew, setAutoRenew] = useState(true);
  const [email, setEmail] = useState(data.acme.email || '');
  const [fullchain, setFullchain] = useState('');
  const [privkey, setPrivkey] = useState('');
  const { busy, run } = useAction();
  const chosen = data.providers.find((p: any) => p.id === provider);

  const submit = () =>
    run('c', async () => {
      let cert;
      if (mode === 'acme') {
        if (!data.acme.email || email !== data.acme.email) await api.put('/api/settings/acme', { email });
        cert = await api.post('/api/certificates', { name, domains, provider_id: provider || null, key_type: keyType, auto_renew: autoRenew });
      } else {
        cert = await api.post('/api/certificates/upload', { name, fullchain, privkey });
      }
      onCreated();
      navigate(`/certificates/${cert.id}`);
    }, mode === 'acme' ? 'Выпуск запущен' : 'Сертификат загружен');

  return (
    <Modal title="Новый сертификат" onClose={onClose} wide>
      <div class="stack">
        <Segmented value={mode} onChange={setMode} options={[{ value: 'acme', label: "Выпустить (Let's Encrypt)" }, { value: 'upload', label: 'Загрузить свой' }]} />
        <Field label="Название" hint="Для списка; по умолчанию — первый домен">
          <input class="input" value={name} onInput={(e) => setName(e.currentTarget.value)} placeholder="Основной wildcard" />
        </Field>
        {mode === 'acme' ? (
          <>
            <Field label="Домены" hint="Enter или запятая — добавить. Wildcard поддерживается на любой глубине: *.a.b.example.com">
              <DomainInput domains={domains} setDomains={setDomains} />
            </Field>
            <div class="form-grid">
              <Field label="Проверка DNS-01" hint={chosen ? (chosen.type === 'cloudflare' ? 'TXT-записи создаются и удаляются автоматически' : `CNAME _acme-challenge → ${chosen.fulldomain}`) : 'Вы публикуете TXT-записи сами; продление тоже потребует действий'}>
                <select class="select" value={provider} onChange={(e) => setProvider(e.currentTarget.value)}>
                  {data.providers.map((p: any) => <option value={p.id} key={p.id}>{p.name} ({p.type === 'cloudflare' ? 'Cloudflare' : 'acme-dns'})</option>)}
                  <option value="">Вручную (TXT-записи)</option>
                </select>
              </Field>
              <Field label="Тип ключа">
                <select class="select" value={keyType} onChange={(e) => setKeyType(e.currentTarget.value)}>
                  <option value="ec256">ECDSA P-256 (рекомендуется)</option>
                  <option value="ec384">ECDSA P-384</option>
                  <option value="rsa2048">RSA 2048</option>
                  <option value="rsa4096">RSA 4096</option>
                </select>
              </Field>
              {!data.acme.email && (
                <Field label="E-mail для Let's Encrypt" hint="Уведомления об истечении от CA">
                  <input class="input" type="email" value={email} onInput={(e) => setEmail(e.currentTarget.value)} placeholder="admin@example.com" />
                </Field>
              )}
            </div>
            {!data.providers.length && (
              <Callout icon="info">
                Для автоматического продления подключите DNS-провайдера: <Link to="/settings/certificates" class="link">Cloudflare или acme-dns</Link>.
                acme-dns работает с любым DNS-хостингом через один CNAME.
              </Callout>
            )}
            <div class="toggle-row">
              <div class="toggle-row__text">
                <div class="toggle-row__title">Автопродление</div>
                <div class="toggle-row__desc">За {data.acme.renew_days} дней до истечения; обновлённый сертификат разойдётся по нодам сам</div>
              </div>
              <Switch on={autoRenew} onChange={setAutoRenew} />
            </div>
          </>
        ) : (
          <div class="form-grid">
            <Field label="fullchain.pem"><textarea class="textarea textarea--mono" rows={8} value={fullchain} onInput={(e) => setFullchain(e.currentTarget.value)} placeholder="-----BEGIN CERTIFICATE-----" /></Field>
            <Field label="privkey.pem"><textarea class="textarea textarea--mono" rows={8} value={privkey} onInput={(e) => setPrivkey(e.currentTarget.value)} placeholder="-----BEGIN PRIVATE KEY-----" /></Field>
          </div>
        )}
        <div class="form-actions">
          <Button variant="plain" onClick={onClose}>Отмена</Button>
          <Button variant="primary" loading={busy === 'c'} icon={mode === 'acme' ? 'zap' : 'upload'}
            disabled={mode === 'acme' ? !domains.length || !email : !fullchain || !privkey} onClick={submit}>
            {mode === 'acme' ? 'Выпустить' : 'Загрузить'}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export function Certificates() {
  const { data, error, loading, reload } = useData(() => api.get('/api/certificates'), [], 10000);
  const [creating, setCreating] = useState(false);
  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  const certs: any[] = data.certificates;
  return (
    <div class="stack">
      <PageHead title="Сертификаты" sub="Выпуск, автопродление и доставка SSL-сертификатов на ноды"
        actions={<>
          <Link to="/settings/certificates" class="btn btn--ghost"><Icon name="settings" size={17} /><span>DNS и ACME</span></Link>
          <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>Новый сертификат</Button>
        </>} />
      {certs.length === 0 ? (
        <div class="card card--dots">
          <Empty icon="certificate" title="Сертификатов пока нет" action={<Button variant="primary" icon="plus" onClick={() => setCreating(true)}>Выпустить сертификат</Button>}>
            Выпустите обычный или wildcard-сертификат через Let's Encrypt (DNS-01) или загрузите свой — затем назначьте его нодам.
          </Empty>
        </div>
      ) : (
        <div class="cert-grid">
          {certs.map((c) => {
            const st = certStatus(c);
            return (
              <div class="card card--interactive cert-card" key={c.id} onClick={() => navigate(`/certificates/${c.id}`)}>
                <div class="row row--between">
                  <span class="stat__icon"><Icon name="certificate" size={18} /></span>
                  <Badge tone={st.tone} size="sm">{st.text}</Badge>
                </div>
                <div class="cert-card__name ellipsis">{c.name}</div>
                <div class="chips">
                  {c.domains.slice(0, 4).map((d: string) => <span class="chip chip--sm" key={d}>{d}</span>)}
                  {c.domains.length > 4 && <span class="tiny faint">+{c.domains.length - 4}</span>}
                </div>
                <ValidityBar from={c.not_before} to={c.not_after} />
                <div class="row row--between tiny faint">
                  <span>{c.not_after ? `до ${dateShort(c.not_after)}` : 'не выпущен'}</span>
                  <span>{c.source === 'upload' ? 'загружен' : c.provider ? c.provider.name : 'ручной DNS'} · {pl(c.nodes.length, ['нода', 'ноды', 'нод'])}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
      {creating && <NewCertificateModal data={data} onClose={() => setCreating(false)} onCreated={reload} />}
    </div>
  );
}

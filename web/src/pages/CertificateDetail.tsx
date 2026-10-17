import { useState } from 'preact/hooks';
import { api } from '../api';
import { Icon } from '../components/Icon';
import {
  Badge, Button, Callout, CodeBox, ErrorState, Link, Loading, PageHead, Switch, confirmDialog, copyText, useAction, useData,
} from '../components/ui';
import { ago, dateTime } from '../format';
import { navigate } from '../state';
import { ValidityBar, certStatus } from './Certificates';

const STAGES: Record<string, string> = {
  account: 'Регистрация аккаунта ACME',
  order: 'Создание заказа',
  dns_publish: 'Публикация TXT-записей',
  dns_wait: 'Ожидание распространения DNS',
  validating: 'Проверка домена удостоверяющим центром',
  finalizing: 'Получение сертификата',
  pending_dns: 'Ожидаются TXT-записи',
  failed: 'Ошибка',
};

export function CertificateDetail({ id }: { id: string }) {
  const { data: c, error, loading, reload } = useData(() => api.get(`/api/certificates/${id}`), [id], 4000);
  const [records, setRecords] = useState<any[] | null>(null);
  const { busy, run } = useAction();
  if (loading && !c) return <Loading />;
  if (error && !c) return <ErrorState error={error} onRetry={reload} />;
  const st = certStatus(c);
  const ch = c.challenge || {};

  const check = () => run('check', async () => setRecords((await api.get(`/api/certificates/${id}/dns-check`)).records));
  const confirm = () => run('confirm', async () => {
    const r = await api.post(`/api/certificates/${id}/confirm-dns`);
    if (!r.ok) throw new Error(`Записи ещё не видны в DNS: ${r.missing.join(', ')}`);
    reload(true);
  }, 'Записи найдены — выпуск продолжается');

  return (
    <div class="stack">
      <PageHead
        crumbs={[{ label: 'Сертификаты', to: '/certificates' }, { label: c.name }]}
        title={c.name}
        sub={<span class="row" style={{ gap: '8px' }}><Badge tone={st.tone}>{st.text}</Badge>{c.source === 'upload' ? 'Загруженный сертификат' : `Let's Encrypt · ${c.provider ? c.provider.name : 'ручная проверка DNS'}`}</span>}
        actions={<>
          {c.source === 'acme' && c.status !== 'pending_dns' && (
            <Button icon="refresh" loading={busy === 'renew' || c.running} onClick={() => run('renew', async () => { await api.post(`/api/certificates/${id}/renew`); reload(true); }, 'Выпуск запущен')}>
              {c.version ? 'Перевыпустить' : 'Выпустить'}
            </Button>
          )}
          {c.version > 0 && <a class="btn btn--ghost" href={`/api/certificates/${id}/download`}><Icon name="download" size={17} /><span>Скачать</span></a>}
          <Button variant="danger-soft" icon="trash" onClick={async () => {
            if (await confirmDialog({ title: 'Удалить сертификат?', text: 'Файлы и закрытый ключ будут удалены из панели. Сначала снимите сертификат с нод.', danger: true, confirm: 'Удалить' })) {
              run('del', async () => { await api.del(`/api/certificates/${id}`); navigate('/certificates'); }, 'Удалён');
            }
          }}>Удалить</Button>
        </>}
      />

      {c.running && (
        <div class="card progress-card">
          <span class="spinner spinner--lg" />
          <div class="grow">
            <b>{STAGES[ch.stage] || 'Выпуск сертификата'}</b>
            {ch.pending?.length > 0 && <div class="tiny muted mono">{ch.pending.join(', ')}</div>}
            <div class="tiny faint">Обычно занимает 1–3 минуты; распространение DNS может занять до 10 минут.</div>
          </div>
        </div>
      )}
      {c.last_error && !c.running && <Callout tone="bad"><b>Последняя попытка не удалась:</b> {c.last_error}</Callout>}

      {c.status === 'pending_dns' && !c.running && ch.records && (
        <div class="card card--dots">
          <div class="card-title" style={{ marginBottom: '6px' }}>Опубликуйте TXT-записи</div>
          <p class="small muted" style={{ marginBottom: '14px' }}>
            Добавьте записи у вашего DNS-провайдера (TTL 60–300). Если для одного имени несколько значений — нужны все записи одновременно.
          </p>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Тип</th><th>Имя</th><th>Значение</th><th>В DNS</th></tr></thead>
              <tbody>
                {ch.records.flatMap((r: any) => r.values.map((v: string) => {
                  const found = records?.find((x) => x.name === r.name);
                  const ok = found ? found.found.includes(v) : null;
                  return (
                    <tr key={r.name + v}>
                      <td><Badge size="sm">TXT</Badge></td>
                      <td><button type="button" class="copyable mono" onClick={() => copyText(r.name)}>{r.name} <Icon name="copy" size={13} /></button></td>
                      <td><button type="button" class="copyable mono" onClick={() => copyText(v)}>{v} <Icon name="copy" size={13} /></button></td>
                      <td>{ok == null ? <span class="faint">—</span> : ok ? <Badge tone="ok" size="sm">найдено</Badge> : <Badge tone="warn" size="sm">нет</Badge>}</td>
                    </tr>
                  );
                }))}
              </tbody>
            </table>
          </div>
          <div class="form-actions">
            <Button icon="search" loading={busy === 'check'} onClick={check}>Проверить DNS</Button>
            <Button variant="primary" icon="arrowRight" loading={busy === 'confirm'} onClick={confirm}>Записи добавлены — выпустить</Button>
          </div>
        </div>
      )}

      <div class="grid grid--2">
        <div class="card">
          <div class="card-head"><div class="card-title">Сертификат</div>{c.version > 0 && <Badge size="sm">версия {c.version}</Badge>}</div>
          <div class="chips" style={{ marginBottom: '16px' }}>
            {c.domains.map((d: string) => <span class="chip" key={d}>{d}</span>)}
          </div>
          {c.not_after && <ValidityBar from={c.not_before} to={c.not_after} />}
          <dl class="kv" style={{ marginTop: '14px' }}>
            <dt>Действует с</dt><dd>{dateTime(c.not_before)}</dd>
            <dt>Действует до</dt><dd>{dateTime(c.not_after)}</dd>
            <dt>Выпущен</dt><dd>{c.issued_at ? ago(c.issued_at) : '—'}</dd>
            <dt>Издатель</dt><dd class="small">{c.issuer || '—'}</dd>
            <dt>Ключ</dt><dd>{c.key_type}</dd>
            <dt>SHA-256</dt><dd class="mono tiny">{c.fingerprint || '—'}</dd>
          </dl>
          {c.source === 'acme' && (
            <div class="toggle-row" style={{ marginTop: '8px' }}>
              <div class="toggle-row__text">
                <div class="toggle-row__title">Автопродление</div>
                <div class="toggle-row__desc">{c.provider ? 'Полностью автоматически' : 'Панель подготовит заказ и попросит обновить TXT-записи'}</div>
              </div>
              <Switch on={!!c.auto_renew} onChange={(v) => run('ar', async () => { await api.patch(`/api/certificates/${id}`, { auto_renew: v }); reload(true); })} />
            </div>
          )}
        </div>
        <div class="card">
          <div class="card-head"><div class="card-title">Используется на нодах</div><span class="tiny faint">{c.nodes.length}</span></div>
          {c.nodes.length === 0 ? (
            <div class="small muted">Назначьте сертификат на странице ноды — раздел «SSL-сертификат». После продления новая версия доставляется на ноды автоматически.</div>
          ) : (
            <div class="top-list">
              {c.nodes.map((n: any) => (
                <Link to={`/nodes/${n.id}`} class="top-list__row" key={n.id}>
                  <Icon name="server" size={16} />
                  <span class="grow">{n.name}</span>
                  {n.domain && (n.covered ? <Badge tone="ok" size="sm">{n.domain}</Badge> : <Badge tone="bad" size="sm">{n.domain} не покрыт</Badge>)}
                </Link>
              ))}
            </div>
          )}
          {c.provider?.type === 'acmedns' && (
            <div style={{ marginTop: '16px' }}>
              <div class="eyebrow" style={{ marginBottom: '8px' }}>CNAME для acme-dns</div>
              <CodeBox text={[...new Set(c.domains.map((d: string) => `_acme-challenge.${d.replace(/^\*\./, '')}`))].map((n) => `${n}  CNAME  ${c.provider.fulldomain || '(см. настройки)'}`).join('\n')} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from 'preact/hooks';
import { api } from '../api';
import { Icon } from '../components/Icon';
import {
  Badge, Button, Callout, ErrorState, Field, Link, Loading, Modal, PageHead, Segmented, Switch, ToggleRow, confirmDialog,
  useAction, useData,
} from '../components/ui';
import { num } from '../format';

export const POLICY_OPTIONS = [
  { value: 'public', label: 'Открыт' },
  { value: 'whitelist', label: 'Белый список' },
  { value: 'closed', label: 'Закрыт' },
];

export const ROLE_LABEL: Record<string, string> = {
  xray: 'Xray inbound',
  remnanode: 'API RemnaNode',
  nginx: 'Nginx',
  ipvs: 'IPVS (балансировка)',
  docker: 'Docker (опубликован)',
  other: 'Другие службы',
  panel: 'Панель Ezhik Guard',
};

export type Rule = { id: string; proto: string; ports: string; sources: string[]; comment: string; enabled: boolean };

export function RuleModal({ rule, onSave, onClose }: { rule?: Rule; onSave: (r: Rule) => void; onClose: () => void }) {
  const [proto, setProto] = useState(rule?.proto || 'tcp');
  const [ports, setPorts] = useState(rule?.ports || '');
  const [sources, setSources] = useState((rule?.sources || []).join('\n'));
  const [comment, setComment] = useState(rule?.comment || '');
  return (
    <Modal title={rule ? 'Правило' : 'Новое правило'} desc="Разрешить входящие соединения" onClose={onClose}>
      <div class="stack">
        <div class="form-grid">
          <Field label="Протокол">
            <Segmented value={proto} onChange={setProto} options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'any', label: 'TCP+UDP' }]} />
          </Field>
          <Field label="Порты" hint="443 · 80,443 · 10000-10100">
            <input class="input input--mono" value={ports} onInput={(e) => setPorts(e.currentTarget.value)} placeholder="443" />
          </Field>
        </div>
        <Field label="Источники" hint="IPv4/IPv6 адреса или подсети CIDR, по одному в строке. Пусто — откуда угодно.">
          <textarea class="textarea textarea--mono" rows={3} value={sources} onInput={(e) => setSources(e.currentTarget.value)} placeholder={'203.0.113.10\n2001:db8::/32'} />
        </Field>
        <Field label="Комментарий"><input class="input" value={comment} onInput={(e) => setComment(e.currentTarget.value)} /></Field>
        <div class="form-actions">
          <Button variant="plain" onClick={onClose}>Отмена</Button>
          <Button variant="primary" disabled={!ports.trim()} onClick={() => onSave({
            id: rule?.id || Math.random().toString(36).slice(2, 10), proto, ports: ports.trim(), comment,
            sources: sources.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean), enabled: rule?.enabled ?? true,
          })}>Сохранить</Button>
        </div>
      </div>
    </Modal>
  );
}

export function RulesTable({ rules, onChange, disabledIds, onToggleGlobal }: {
  rules: Rule[]; onChange?: (r: Rule[]) => void; disabledIds?: string[]; onToggleGlobal?: (id: string, on: boolean) => void;
}) {
  const [editing, setEditing] = useState<Rule | null | undefined>(undefined);
  return (
    <>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Вкл</th><th>Протокол</th><th>Порты</th><th>Источники</th><th>Комментарий</th><th class="col-actions" /></tr></thead>
          <tbody>
            {rules.length === 0 && <tr><td colSpan={6} class="small faint">Правил нет</td></tr>}
            {rules.map((r, i) => {
              const on = onToggleGlobal ? !(disabledIds || []).includes(r.id) : r.enabled;
              return (
                <tr key={r.id}>
                  <td><Switch on={on} onChange={(v) => onToggleGlobal ? onToggleGlobal(r.id, v) : onChange?.(rules.map((x, j) => (j === i ? { ...x, enabled: v } : x)))} /></td>
                  <td><Badge size="sm">{r.proto === 'any' ? 'TCP+UDP' : r.proto.toUpperCase()}</Badge></td>
                  <td class="mono">{r.ports}</td>
                  <td class="mono tiny">{r.sources.length ? r.sources.join(', ') : <span class="faint">все</span>}</td>
                  <td class="small">{r.comment}</td>
                  <td class="col-actions">
                    {onChange && (
                      <div class="row" style={{ gap: '4px' }}>
                        <button type="button" class="icon-btn icon-btn--sm" title="Изменить" onClick={() => setEditing(r)}><Icon name="edit" size={14} /></button>
                        <button type="button" class="icon-btn icon-btn--sm icon-btn--danger" title="Удалить" onClick={() => onChange(rules.filter((_, j) => j !== i))}><Icon name="trash" size={14} /></button>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {onChange && <div style={{ padding: '12px 16px' }}><Button size="sm" icon="plus" onClick={() => setEditing(null)}>Добавить правило</Button></div>}
      {editing !== undefined && (
        <RuleModal rule={editing || undefined} onClose={() => setEditing(undefined)} onSave={(rule) => {
          onChange?.(editing ? rules.map((x) => (x.id === rule.id ? rule : x)) : [...rules, rule]);
          setEditing(undefined);
        }} />
      )}
    </>
  );
}

export function Firewall() {
  const { data, error, loading, reload } = useData(() => api.get('/api/settings/firewall'), []);
  const { data: nodes, reload: reloadNodes } = useData(() => api.get('/api/nodes'), [], 15000);
  const [fw, setFw] = useState<any>(null);
  const [whitelist, setWhitelist] = useState('');
  const { busy, run } = useAction();
  useEffect(() => {
    if (data) {
      setFw(data.firewall);
      setWhitelist((data.firewall.remnanode_sources || []).join('\n'));
    }
  }, [data]);
  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  if (!fw) return <Loading />;
  const dirty = JSON.stringify({ ...fw, remnanode_sources: whitelist.split(/[\s,]+/).filter(Boolean) }) !== JSON.stringify(data.firewall);
  const save = () => run('save', async () => {
    const saved = await api.put('/api/settings/firewall', { ...fw, remnanode_sources: whitelist.split(/[\s,]+/).filter(Boolean) });
    setFw(saved);
    reload(true);
  }, 'Правила сохранены и отправлены на ноды');
  const list: any[] = nodes?.nodes || [];

  return (
    <div class="stack">
      <PageHead title="Firewall" sub="Единые правила входящих соединений для всех нод с переопределениями на каждой ноде" />
      <Callout icon="shield">
        Ezhik Guard использует собственную таблицу nftables и не трогает правила Docker, fail2ban, ufw и других служб.
        SSH всегда остаётся доступным, уже установленные соединения не рвутся, а если после применения нода потеряет связь с панелью —
        правила автоматически откатятся через {fw.confirm_seconds} с.
      </Callout>

      <div class="card">
        <div class="card-head"><div class="card-title">Глобальные правила</div><span class="tiny faint">разрешено; всё остальное — запрещено</span></div>
        <div class="card card--flush" style={{ boxShadow: 'none' }}>
          <RulesTable rules={fw.rules} onChange={(rules) => setFw({ ...fw, rules })} />
        </div>
      </div>

      <div class="grid grid--2">
        <div class="card">
          <div class="card-title" style={{ marginBottom: '6px' }}>Автоматически обнаруженные порты</div>
          <p class="small muted" style={{ marginBottom: '12px' }}>Агент видит, что слушает на ноде. Политика по умолчанию для каждого типа (на ноде можно изменить для конкретного порта).</p>
          {Object.keys(ROLE_LABEL).filter((r) => r !== 'panel').map((role) => (
            <div class="toggle-row" key={role}>
              <div class="toggle-row__text"><div class="toggle-row__title">{ROLE_LABEL[role]}</div></div>
              <Segmented value={fw.auto[role]} onChange={(v) => setFw({ ...fw, auto: { ...fw.auto, [role]: v } })} options={POLICY_OPTIONS} />
            </div>
          ))}
        </div>
        <div class="card">
          <div class="card-title" style={{ marginBottom: '12px' }}>Белый список</div>
          <p class="small muted" style={{ marginBottom: '10px' }}>
            Для портов с политикой «Белый список» (по умолчанию — API RemnaNode). IP панели Remnawave добавляются автоматически
            {data.remnawave_ips?.length ? <>: <span class="mono">{data.remnawave_ips.join(', ')}</span></> : ' (Remnawave не настроен или ещё не опрошен)'}.
          </p>
          <Field label="Дополнительные адреса" hint="IP или CIDR, по одному в строке">
            <textarea class="textarea textarea--mono" rows={4} value={whitelist} onInput={(e) => setWhitelist(e.currentTarget.value)} />
          </Field>
          <div class="divider" />
          <ToggleRow title="Включать на новых нодах" desc="Для существующих нод — переключатель на странице ноды или массово ниже" on={fw.enabled_default} onChange={(v) => setFw({ ...fw, enabled_default: v })} />
          <ToggleRow title="Разрешить ping (ICMP)" on={fw.icmp} onChange={(v) => setFw({ ...fw, icmp: v })} />
          <ToggleRow title="Защита SSH от блокировки" desc="Порты sshd всегда открыты" on={fw.anti_lockout} onChange={(v) => setFw({ ...fw, anti_lockout: v })} />
          <Field label="Таймер автоотката, секунд"><input class="input" type="number" min={30} max={600} value={fw.confirm_seconds} onInput={(e) => setFw({ ...fw, confirm_seconds: Number(e.currentTarget.value) })} /></Field>
        </div>
      </div>
      <div class="form-actions" style={{ marginTop: 0 }}>
        <Button variant="primary" loading={busy === 'save'} disabled={!dirty} onClick={save}>Сохранить</Button>
      </div>

      <div class="card card--flush">
        <div class="card-head" style={{ padding: '18px 20px 6px' }}><div class="card-title">Состояние на нодах</div></div>
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th>Нода</th><th>Firewall</th><th>Отброшено пакетов</th><th>BBR</th><th class="col-actions" /></tr></thead>
            <tbody>
              {list.map((n) => {
                const on = n.firewall_state?.active;
                return (
                  <tr key={n.id}>
                    <td><Link to={`/nodes/${n.id}`}>{n.name}</Link></td>
                    <td>{on ? <Badge tone="ok" size="sm">активен</Badge> : <Badge size="sm">выключен</Badge>}{n.components?.firewall && !n.components.firewall.ok && <div class="tiny bad-text">{n.components.firewall.message}</div>}</td>
                    <td class="num">{on ? num(n.firewall_state?.dropped_packets || 0) : '—'}</td>
                    <td>{n.bbr_state?.congestion === 'bbr' ? <Badge tone="ok" size="sm">bbr</Badge> : <span class="faint">{n.bbr_state?.congestion || '—'}</span>}</td>
                    <td class="col-actions">
                      <Button size="sm" variant={on ? 'ghost' : 'soft'} onClick={async () => {
                        if (!on && !(await confirmDialog({ title: `Включить firewall на ${n.name}?`, text: 'Перед включением откройте страницу ноды и проверьте список обнаруженных портов. Всё, что не разрешено, будет закрыто.', confirm: 'Включить' }))) return;
                        run('n' + n.id, async () => { await api.patch(`/api/nodes/${n.id}`, { firewall: { ...(n.firewall_override || {}), enabled: !on } }); reloadNodes(true); }, on ? 'Firewall выключается' : 'Firewall включается');
                      }}>{on ? 'Выключить' : 'Включить'}</Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
      <Network data={data} reload={() => reload(true)} />
    </div>
  );
}

function Network({ data, reload }: { data: any; reload: () => void }) {
  const { busy, run } = useAction();
  return (
    <div class="card">
      <ToggleRow title={<span class="row" style={{ gap: '8px' }}><Icon name="zap" size={17} /> BBR по умолчанию</span>}
        desc="TCP BBR + fq ускоряет передачу на каналах с потерями. Применяется ко всем нодам, где не задано явно."
        on={!!data.network?.bbr_default}
        onChange={(v) => run('bbr', async () => { await api.put('/api/settings/network', { bbr_default: v }); reload(); }, v ? 'BBR будет включён на нодах' : 'Сохранено')}
        extra={busy === 'bbr' ? <span class="spinner" /> : undefined} />
    </div>
  );
}

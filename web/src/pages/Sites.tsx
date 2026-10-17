import { useRef, useState } from 'preact/hooks';
import { api, csrfToken } from '../api';
import { Icon } from '../components/Icon';
import {
  Badge, Button, Callout, Empty, ErrorState, Field, Link, Loading, Modal, PageHead, confirmDialog, useAction, useData,
} from '../components/ui';
import { bytes, dateTime } from '../format';
import { toast, toastError } from '../state';

export async function openPreview(path: string) {
  try {
    const r = await api.get(path);
    window.open(r.url, '_blank', 'noopener');
  } catch (e) {
    toastError(e);
  }
}

function UploadModal({ site, onClose, onDone }: { site?: any; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState('');
  const [note, setNote] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const input = useRef<HTMLInputElement>(null);
  const upload = async () => {
    if (!file) return;
    setBusy(true);
    try {
      const form = new FormData();
      form.append('file', file);
      form.append('name', name);
      form.append('note', note);
      if (site) form.append('site_id', site.id);
      const response = await fetch('/api/sites/upload', { method: 'POST', body: form, credentials: 'same-origin',
        headers: { 'X-CSRF-Token': csrfToken() } });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `Ошибка ${response.status}`);
      setResult(data);
      onDone();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  if (result) {
    return (
      <Modal title="Загружено" onClose={onClose}>
        <div class="stack">
          <Callout tone="ok" icon="check">
            {result.files} файлов{result.site.current_version === result.version ? ' — версия опубликована' : ' — сохранено как черновик. Проверьте предпросмотр и опубликуйте.'}
          </Callout>
          {result.skipped?.length > 0 && <Callout tone="warn">Пропущены файлы неподдерживаемых типов: {result.skipped.join(', ')}</Callout>}
          <div class="form-actions">
            <Button icon="eye" onClick={() => openPreview(`/api/sites/${result.site.id}/preview?version=${result.version}`)}>Предпросмотр</Button>
            <Button variant="primary" onClick={onClose}>Готово</Button>
          </div>
        </div>
      </Modal>
    );
  }
  return (
    <Modal title={site ? `Новая версия: ${site.name}` : 'Новый сайт-заглушка'} desc="ZIP-архив со статическим сайтом: index.html в корне (или в единственной папке), CSS, JS, изображения, шрифты." onClose={onClose}>
      <div class="stack">
        {!site && <Field label="Название"><input class="input" value={name} onInput={(e) => setName(e.currentTarget.value)} placeholder="Корпоративный сайт" /></Field>}
        <div class={`dropzone ${file ? 'has-file' : ''}`} onClick={() => input.current?.click()}
          onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); const f = e.dataTransfer?.files?.[0]; if (f) setFile(f); }}>
          <Icon name="upload" size={22} />
          <div>{file ? <><b>{file.name}</b> · {bytes(file.size)}</> : 'Перетащите ZIP сюда или нажмите, чтобы выбрать'}</div>
          <input ref={input} type="file" accept=".zip,application/zip" hidden onChange={(e) => setFile(e.currentTarget.files?.[0] || null)} />
        </div>
        <Field label="Комментарий к версии"><input class="input" value={note} onInput={(e) => setNote(e.currentTarget.value)} /></Field>
        <p class="tiny faint">Скрипты сайта в предпросмотре работают в изолированной песочнице и не имеют доступа к панели. Серверный код (PHP и т. п.) не поддерживается.</p>
        <div class="form-actions">
          <Button variant="plain" onClick={onClose}>Отмена</Button>
          <Button variant="primary" icon="upload" loading={busy} disabled={!file} onClick={upload}>Загрузить</Button>
        </div>
      </div>
    </Modal>
  );
}

export function Sites() {
  const { data, error, loading, reload } = useData(() => api.get('/api/sites'), [], 15000);
  const [uploading, setUploading] = useState<any>(undefined);
  const { busy, run } = useAction();
  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  const sites: any[] = data.sites;
  return (
    <div class="stack">
      <PageHead title="Сайты-заглушки" sub="Сайт, который видят посетители нод в режимах Nginx Frontend и Vision + TLS"
        actions={<>
          <Button icon="eye" onClick={() => window.open('/site-mask/', '_blank', 'noopener')}>Предпросмотр сайта</Button>
          <Button variant="primary" icon="plus" onClick={() => setUploading(null)}>Загрузить сайт</Button>
        </>} />
      {sites.length === 0 ? (
        <div class="card card--dots">
          <Empty icon="globe" title="Сайтов пока нет" action={<Button variant="primary" icon="upload" onClick={() => setUploading(null)}>Загрузить ZIP</Button>}>
            Пока сайт не загружен, ноды показывают нейтральную встроенную страницу «Site is under construction».
          </Empty>
        </div>
      ) : sites.map((site) => (
        <div class="card" key={site.id}>
          <div class="card-head">
            <div>
              <div class="card-title row" style={{ gap: '8px' }}>{site.name}{site.is_default ? <Badge tone="accent" size="sm">по умолчанию для всех нод</Badge> : null}</div>
              <div class="tiny faint">Опубликована версия {site.current_version || '—'}{site.nodes.length ? ` · индивидуально назначен: ${site.nodes.map((n: any) => n.name).join(', ')}` : ''}</div>
            </div>
            <div class="row row--wrap">
              <Button size="sm" icon="eye" onClick={() => openPreview(`/api/sites/${site.id}/preview?version=${site.current_version || ''}`)}>Предпросмотр</Button>
              <Button size="sm" icon="upload" onClick={() => setUploading(site)}>Новая версия</Button>
              {!site.is_default && <Button size="sm" onClick={() => run('d', async () => { await api.patch(`/api/sites/${site.id}`, { is_default: true }); reload(true); }, 'Сайт назначен по умолчанию')}>Сделать основным</Button>}
              <button type="button" class="icon-btn icon-btn--sm icon-btn--danger" title="Удалить сайт" onClick={async () => {
                if (await confirmDialog({ title: `Удалить «${site.name}»?`, danger: true, confirm: 'Удалить' })) run('x', async () => { await api.del(`/api/sites/${site.id}`); reload(true); }, 'Удалён');
              }}><Icon name="trash" size={15} /></button>
            </div>
          </div>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Версия</th><th>Файлов</th><th>Размер</th><th>Комментарий</th><th>Статус</th><th class="col-actions" /></tr></thead>
              <tbody>
                {site.versions.map((v: any) => (
                  <tr key={v.version}>
                    <td class="small">{dateTime(v.created_at)}</td>
                    <td class="num">{v.files}</td>
                    <td>{bytes(v.size)}</td>
                    <td class="small">{v.note}</td>
                    <td>{v.version === site.current_version ? <Badge tone="ok" size="sm">опубликована</Badge> : v.version === site.draft_version ? <Badge tone="warn" size="sm">черновик</Badge> : <Badge size="sm">архив</Badge>}</td>
                    <td class="col-actions">
                      <div class="row" style={{ gap: '4px' }}>
                        <Button size="sm" variant="plain" icon="eye" onClick={() => openPreview(`/api/sites/${site.id}/preview?version=${v.version}`)}>Открыть</Button>
                        {v.version !== site.current_version && <Button size="sm" variant="soft" loading={busy === 'p' + v.version} onClick={() => run('p' + v.version, async () => { await api.post(`/api/sites/${site.id}/publish`, { version: v.version }); reload(true); }, 'Опубликовано — ноды обновят сайт автоматически')}>Опубликовать</Button>}
                        {v.version !== site.current_version && <button type="button" class="icon-btn icon-btn--sm icon-btn--danger" title="Удалить версию" onClick={() => run('dv', async () => { await api.del(`/api/sites/${site.id}/versions/${v.version}`); reload(true); })}><Icon name="trash" size={14} /></button>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
      <div class="card card--flush">
        <div class="card-head" style={{ padding: '18px 20px 6px' }}><div class="card-title">Распространение на ноды</div><span class="tiny faint">ноды в режимах Frontend и Vision</span></div>
        {data.nodes.length === 0 ? <div class="small faint" style={{ padding: '0 20px 18px' }}>Нет нод в режимах Frontend или Vision.</div> : (
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Нода</th><th>Сайт</th><th>Нужная версия</th><th>Установлена</th><th /></tr></thead>
              <tbody>
                {data.nodes.map((n: any) => (
                  <tr key={n.id}>
                    <td><Link to={`/nodes/${n.id}`}>{n.name}</Link></td>
                    <td>{n.site}</td>
                    <td class="mono tiny">{n.wanted}</td>
                    <td class="mono tiny">{n.installed || '—'}</td>
                    <td>{!n.online ? <Badge size="sm">офлайн</Badge> : n.installed === n.wanted ? <Badge tone="ok" size="sm">синхронизирована</Badge> : <Badge tone="warn" size="sm">обновляется</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {uploading !== undefined && <UploadModal site={uploading || undefined} onClose={() => setUploading(undefined)} onDone={() => { reload(true); toast('Сайт загружен'); }} />}
    </div>
  );
}

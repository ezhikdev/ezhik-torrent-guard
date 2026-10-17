import { useEffect, useState } from 'preact/hooks';
import { api } from '../api';
import { EventRow } from '../components/events';
import { Icon } from '../components/Icon';
import { Button, Empty, ErrorState, Loading, PageHead, useData } from '../components/ui';

const TYPES = [
  { value: 'torrent', label: 'Торренты' },
  { value: 'p2p', label: 'P2P / DHT' },
  { value: 'scan', label: 'Сканирование' },
  { value: 'sanction', label: 'Блокировки' },
  { value: 'node', label: 'Ноды' },
  { value: 'cert', label: 'Сертификаты' },
];

export function Events() {
  const [types, setTypes] = useState<string[]>([]);
  const [node, setNode] = useState('');
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [items, setItems] = useState<any[]>([]);
  const [more, setMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const { data: nodes } = useData(() => api.get('/api/nodes'), []);

  useEffect(() => {
    const t = setTimeout(() => setQuery(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);

  const url = (before = 0) => {
    const p = new URLSearchParams({ limit: '100' });
    if (types.length) p.set('type', types.join(','));
    if (node) p.set('node', node);
    if (/^\d+$/.test(query)) p.set('client', query);
    else if (query) p.set('q', query);
    if (before) p.set('before', String(before));
    return `/api/events?${p}`;
  };
  const { data, error, loading, reload } = useData(() => api.get(url()), [types.join(','), node, query], 15000);
  useEffect(() => {
    if (data) {
      setItems(data.events);
      setMore(data.events.length === 100);
    }
  }, [data]);

  const loadMore = async () => {
    setLoadingMore(true);
    try {
      const last = items[items.length - 1];
      const next = await api.get(url(last.detected_at));
      setItems([...items, ...next.events]);
      setMore(next.events.length === 100);
    } finally {
      setLoadingMore(false);
    }
  };

  const toggle = (t: string) => setTypes(types.includes(t) ? types.filter((x) => x !== t) : [...types, t]);

  return (
    <div class="stack">
      <PageHead title="События" sub="Обнаружения, блокировки, состояние нод и сертификатов" />
      <div class="toolbar">
        <div class="input-group toolbar__search">
          <Icon name="search" size={16} />
          <input class="input" placeholder="ID клиента или текст" value={q} onInput={(e) => setQ(e.currentTarget.value)} />
        </div>
        <select class="select toolbar__select" value={node} onChange={(e) => setNode(e.currentTarget.value)}>
          <option value="">Все ноды</option>
          {(nodes?.nodes || []).map((n: any) => <option value={n.id} key={n.id}>{n.name}</option>)}
        </select>
        <div class="chips">
          {TYPES.map((t) => (
            <button type="button" key={t.value} class={`filter-chip ${types.includes(t.value) ? 'is-active' : ''}`} onClick={() => toggle(t.value)}>
              {t.label}
            </button>
          ))}
        </div>
      </div>
      {loading && !data ? <Loading /> : error && !data ? <ErrorState error={error} onRetry={reload} /> : (
        <div class="card card--flush">
          {items.length === 0 ? (
            <Empty icon="list" title="Событий нет">По выбранным фильтрам ничего не найдено.</Empty>
          ) : (
            <div class="event-list">{items.map((e) => <EventRow event={e} key={e.id} />)}</div>
          )}
        </div>
      )}
      {more && <div class="center"><Button loading={loadingMore} onClick={loadMore}>Показать ещё</Button></div>}
    </div>
  );
}

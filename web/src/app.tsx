import type { JSX } from 'preact';
import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { api, loadSession, logout, session } from './api';
import { ShapeDefs, ThemeToggle } from './components/expressive';
import { Icon } from './components/Icon';
import { ConfirmHost, Link, Loading } from './components/ui';
import { useThumbStretch } from './motion';
import { CertificateDetail } from './pages/CertificateDetail';
import { Certificates } from './pages/Certificates';
import { Dashboard } from './pages/Dashboard';
import { Events } from './pages/Events';
import { Firewall } from './pages/Firewall';
import { Login } from './pages/Login';
import { NodeDetail } from './pages/NodeDetail';
import { Nodes } from './pages/Nodes';
import { Sanctions } from './pages/Sanctions';
import { Settings } from './pages/Settings';
import { Sites } from './pages/Sites';
import { toasts, useRoute, useSignal } from './state';

type NavItem = { to: string; label: string; icon: string; badge?: string; match?: string };

const MONITORING: NavItem[] = [
  { to: '/', label: 'Обзор', icon: 'activity' },
  { to: '/nodes', label: 'Ноды', icon: 'server', badge: 'nodes' },
  { to: '/events', label: 'События', icon: 'list' },
  { to: '/sanctions', label: 'Блокировки', icon: 'ban', badge: 'sanctions' },
  { to: '/certificates', label: 'Сертификаты', icon: 'certificate', badge: 'certs' },
];

const MANAGEMENT: NavItem[] = [
  { to: '/firewall', label: 'Firewall', icon: 'shield' },
  { to: '/sites', label: 'Сайты', icon: 'globe' },
  { to: '/settings/protection', label: 'Настройки', icon: 'settings', match: '/settings' },
];

const NAV = [...MONITORING, ...MANAGEMENT];

/** Calm tonal backdrop: two slow soft glows. Also hosts the shape clip paths. */
function Backdrop() {
  return (
    <div class="backdrop" aria-hidden="true">
      <ShapeDefs />
      <div class="backdrop__glow backdrop__glow--a" />
      <div class="backdrop__glow backdrop__glow--b" />
    </div>
  );
}

function Toasts() {
  const items = useSignal(toasts);
  return (
    <div class="toasts" aria-live="polite">
      {items.map((t) => (
        <div class={`toast toast--${t.kind} ${t.leaving ? 'is-leaving' : ''}`} key={t.id}>
          <Icon name={t.kind === 'error' ? 'alert' : t.kind === 'ok' ? 'check' : 'info'} size={18} />
          <div>{t.text}</div>
        </div>
      ))}
    </div>
  );
}

function useBadges(active: boolean) {
  const [badges, setBadges] = useState<Record<string, { n: number; muted?: boolean }>>({});
  useEffect(() => {
    if (!active) return;
    let stop = false;
    const load = async () => {
      try {
        const d = await api.get('/api/dashboard');
        if (stop) return;
        setBadges({
          nodes: { n: d.nodes.offline + d.nodes.problems },
          sanctions: { n: d.sanctions.active + d.sanctions.pending, muted: true },
          certs: { n: d.certificates.expiring.length + d.certificates.failed },
        });
      } catch {
        /* the page shows its own errors */
      }
    };
    load();
    const timer = setInterval(load, 30000);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, [active]);
  return badges;
}

function Router({ parts }: { parts: string[] }) {
  if (parts[0] === 'nodes' && parts[1]) return <NodeDetail id={parts[1]} />;
  if (parts[0] === 'nodes') return <Nodes />;
  if (parts[0] === 'events') return <Events />;
  if (parts[0] === 'sanctions') return <Sanctions />;
  if (parts[0] === 'certificates' && parts[1]) return <CertificateDetail id={parts[1]} />;
  if (parts[0] === 'certificates') return <Certificates />;
  if (parts[0] === 'firewall') return <Firewall />;
  if (parts[0] === 'sites') return <Sites />;
  if (parts[0] === 'settings') return <Settings tab={parts[1]} />;
  return <Dashboard />;
}

const isActive = (path: string, item: NavItem) => {
  const to = item.match ?? item.to;
  return to === '/' ? path === '/' : path === to || path.startsWith(`${to}/`);
};

type User = { username: string; version: string };

/**
 * Navigation rail. One pill indicator sits behind the active item and glides
 * (stretching like a drop) when the page changes.
 */
function Sidebar({ path, badges, user }: { path: string; badges: Record<string, { n: number; muted?: boolean }>; user: User }) {
  const ref = useRef<HTMLElement>(null);
  const thumb = useRef<HTMLSpanElement>(null);
  const [box, setBox] = useState<{ y: number; h: number } | null>(null);
  const [ready, setReady] = useState(false);
  const index = NAV.findIndex((item) => isActive(path, item));
  const prevIndex = useRef(index);
  const distance = Math.abs(index - prevIndex.current);
  prevIndex.current = index;
  useThumbStretch(thumb, index, distance, true);

  useLayoutEffect(() => {
    const measure = () => {
      const el = ref.current?.querySelector<HTMLElement>('.nav-item.is-active');
      setBox(el ? { y: el.offsetTop, h: el.offsetHeight } : null);
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [path]);

  useEffect(() => {
    // The first placement must not slide in from the top of the rail.
    if (box && !ready) {
      const id = requestAnimationFrame(() => setReady(true));
      return () => cancelAnimationFrame(id);
    }
  }, [box]);

  const item = (it: NavItem) => {
    const active = isActive(path, it);
    const badge = it.badge ? badges[it.badge] : undefined;
    return (
      <Link to={it.to} class={`nav-item ${active ? 'is-active' : ''}`} key={it.to}>
        <Icon name={it.icon} size={20} stroke={active ? 2.1 : 1.75} />
        {it.label}
        {badge && badge.n > 0 && <span class={`nav-item__count ${badge.muted ? 'nav-item__count--muted' : ''}`}>{badge.n}</span>}
      </Link>
    );
  };

  return (
    <aside class={`sidebar ${box ? 'has-thumb' : ''}`} ref={ref}>
      <span
        ref={thumb}
        class={`nav-thumb ${box ? '' : 'is-hidden'}`}
        style={{ '--thumb-y': `${box?.y ?? 0}px`, '--thumb-h': `${box?.h ?? 48}px`, transition: ready ? undefined : 'none' } as JSX.CSSProperties}
        aria-hidden="true"
      />
      <div class="brand">
        <span class="brand__logo">
          <img src="/logo.png" width={26} height={26} alt="" />
        </span>
        <div>
          <div class="brand__name">Ezhik Guard</div>
          <div class="brand__sub">v{user.version}</div>
        </div>
      </div>
      <div class="nav-section">Мониторинг</div>
      {MONITORING.map(item)}
      <div class="nav-section">Управление</div>
      {MANAGEMENT.map(item)}
      <div class="sidebar__foot">
        <ThemeToggle withLabel />
        <div class="user-chip">
          <span class="avatar">{user.username.slice(0, 1)}</span>
          <div class="grow">
            <div class="ellipsis" style={{ fontWeight: 650 }}>{user.username}</div>
            <div class="tiny faint">администратор</div>
          </div>
          <button type="button" class="icon-btn icon-btn--sm" title="Выйти" aria-label="Выйти" onClick={logout}>
            <Icon name="logout" size={16} />
          </button>
        </div>
      </div>
    </aside>
  );
}

export function App() {
  const user = useSignal(session);
  const { path } = useRoute();
  const [navOpen, setNavOpen] = useState(false);
  const badges = useBadges(!!user);

  useEffect(() => {
    loadSession();
  }, []);
  useEffect(() => setNavOpen(false), [path]);

  if (user === undefined) {
    return (
      <>
        <Backdrop />
        <Loading />
      </>
    );
  }
  if (user === null) {
    return (
      <>
        <Backdrop />
        <Login />
        <Toasts />
      </>
    );
  }

  const parts = path.split('/').filter(Boolean);
  // A new screen springs in; tabs inside one page (settings) keep their state.
  const screenKey = parts[0] === 'nodes' || parts[0] === 'certificates' ? parts.slice(0, 2).join('/') : parts[0] || 'home';

  return (
    <div class={`shell ${navOpen ? 'nav-open' : ''}`}>
      <Backdrop />
      {navOpen && <div class="scrim" onClick={() => setNavOpen(false)} />}
      <Sidebar path={path} badges={badges} user={user} />
      <div class="main-wrap">
        <div class="mobilebar">
          <button type="button" class="icon-btn" onClick={() => setNavOpen(true)} aria-label="Меню">
            <Icon name="menu" size={19} />
          </button>
          <span class="mobilebar__brand">
            <img src="/logo.png" width={24} height={24} alt="" />
            Ezhik Guard
          </span>
          <ThemeToggle />
        </div>
        <main class="main">
          <div class="content screen" key={screenKey}>
            <Router parts={parts} />
          </div>
        </main>
      </div>
      <ConfirmHost />
      <Toasts />
    </div>
  );
}

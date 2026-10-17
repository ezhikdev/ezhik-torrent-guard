import { useEffect, useState } from 'preact/hooks';
import { api, loadSession, logout, session } from './api';
import { Icon } from './components/Icon';
import { ConfirmHost, Link, Loading } from './components/ui';
import { CertificateDetail } from './pages/CertificateDetail';
import { Certificates } from './pages/Certificates';
import { Dashboard } from './pages/Dashboard';
import { Events } from './pages/Events';
import { Login } from './pages/Login';
import { NodeDetail } from './pages/NodeDetail';
import { Nodes } from './pages/Nodes';
import { Sanctions } from './pages/Sanctions';
import { Settings } from './pages/Settings';
import { theme, toasts, toggleTheme, useRoute, useSignal } from './state';

const NAV = [
  { to: '/', label: 'Обзор', icon: 'activity' },
  { to: '/nodes', label: 'Ноды', icon: 'server', badge: 'nodes' },
  { to: '/events', label: 'События', icon: 'list' },
  { to: '/sanctions', label: 'Блокировки', icon: 'ban', badge: 'sanctions' },
  { to: '/certificates', label: 'Сертификаты', icon: 'certificate', badge: 'certs' },
];

function Backdrop() {
  return (
    <div class="backdrop" aria-hidden="true">
      <div class="backdrop__grid" />
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
        <div class={`toast toast--${t.kind}`} key={t.id}>
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

function Router() {
  const { path } = useRoute();
  const parts = path.split('/').filter(Boolean);
  if (parts[0] === 'nodes' && parts[1]) return <NodeDetail id={parts[1]} />;
  if (parts[0] === 'nodes') return <Nodes />;
  if (parts[0] === 'events') return <Events />;
  if (parts[0] === 'sanctions') return <Sanctions />;
  if (parts[0] === 'certificates' && parts[1]) return <CertificateDetail id={parts[1]} />;
  if (parts[0] === 'certificates') return <Certificates />;
  if (parts[0] === 'settings') return <Settings tab={parts[1]} />;
  return <Dashboard />;
}

export function App() {
  const user = useSignal(session);
  const currentTheme = useSignal(theme);
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

  const isActive = (to: string) => (to === '/' ? path === '/' : path.startsWith(to));

  return (
    <div class={`shell ${navOpen ? 'nav-open' : ''}`}>
      <Backdrop />
      {navOpen && <div class="scrim" onClick={() => setNavOpen(false)} />}
      <aside class="sidebar">
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
        {NAV.map((item) => {
          const badge = item.badge ? badges[item.badge] : undefined;
          return (
            <Link to={item.to} class={`nav-item ${isActive(item.to) ? 'is-active' : ''}`} key={item.to}>
              <Icon name={item.icon} size={19} />
              {item.label}
              {badge && badge.n > 0 && <span class={`nav-item__count ${badge.muted ? 'nav-item__count--muted' : ''}`}>{badge.n}</span>}
            </Link>
          );
        })}
        <div class="nav-section">Управление</div>
        <Link to="/settings/protection" class={`nav-item ${isActive('/settings') ? 'is-active' : ''}`}>
          <Icon name="settings" size={19} />
          Настройки
        </Link>
        <div class="sidebar__foot">
          <button type="button" class="nav-item" onClick={toggleTheme}>
            <Icon name={currentTheme === 'dark' ? 'sun' : 'moon'} size={19} />
            {currentTheme === 'dark' ? 'Светлая тема' : 'Тёмная тема'}
          </button>
          <div class="user-chip">
            <span class="avatar">{user.username.slice(0, 1)}</span>
            <div class="grow">
              <div class="ellipsis" style={{ fontWeight: 580 }}>{user.username}</div>
              <div class="tiny faint">администратор</div>
            </div>
            <button type="button" class="icon-btn icon-btn--sm" title="Выйти" onClick={logout}>
              <Icon name="logout" size={15} />
            </button>
          </div>
        </div>
      </aside>
      <div class="main-wrap">
        <div class="mobilebar">
          <button type="button" class="icon-btn" onClick={() => setNavOpen(true)} aria-label="Меню">
            <Icon name="menu" size={18} />
          </button>
          <img src="/logo.png" width={24} height={24} alt="" style={{ filter: 'var(--logo-filter)' }} />
          <b>Ezhik Guard</b>
        </div>
        <main class="main">
          <div class="content">
            <Router />
          </div>
        </main>
      </div>
      <ConfirmHost />
      <Toasts />
    </div>
  );
}

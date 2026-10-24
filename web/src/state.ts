import { useEffect, useState } from 'preact/hooks';

/** Minimal observable value with a hook (no external state library). */
export function signal<T>(initial: T) {
  let value = initial;
  const listeners = new Set<(v: T) => void>();
  return {
    get: () => value,
    set(next: T) {
      value = next;
      listeners.forEach((fn) => fn(value));
    },
    subscribe(fn: (v: T) => void) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
}

export type Signal<T> = ReturnType<typeof signal<T>>;

export function useSignal<T>(s: Signal<T>): T {
  const [value, setValue] = useState(s.get());
  useEffect(() => {
    setValue(s.get());
    const off = s.subscribe(setValue);
    return () => {
      off();
    };
  }, [s]);
  return value;
}

// ------------------------------------------------------------------ router

export const route = signal(location.pathname + location.search);

export function navigate(to: string, replace = false) {
  if (to === location.pathname + location.search) return;
  if (replace) history.replaceState(null, '', to);
  else history.pushState(null, '', to);
  route.set(to);
  window.scrollTo({ top: 0 });
}

window.addEventListener('popstate', () => route.set(location.pathname + location.search));

export function useRoute() {
  const full = useSignal(route);
  const [path, query = ''] = full.split('?');
  return { path, params: new URLSearchParams(query) };
}

// ------------------------------------------------------------------ toasts

export type Toast = { id: number; kind: 'ok' | 'error' | 'info'; text: string; leaving?: boolean };
export const toasts = signal<Toast[]>([]);
let toastId = 0;

export function toast(text: string, kind: Toast['kind'] = 'ok') {
  const item = { id: ++toastId, kind, text };
  toasts.set([...toasts.get().slice(-3), item]);
  const ttl = kind === 'error' ? 7000 : 3800;
  // The snackbar plays its exit first, then leaves the list.
  setTimeout(() => toasts.set(toasts.get().map((t) => (t.id === item.id ? { ...t, leaving: true } : t))), ttl);
  setTimeout(() => toasts.set(toasts.get().filter((t) => t.id !== item.id)), ttl + 240);
}

export function toastError(error: unknown) {
  toast(error instanceof Error ? error.message : String(error), 'error');
}

// ------------------------------------------------------------------ theme

export const theme = signal<string>(document.documentElement.dataset.theme || 'dark');

type ViewTransitionDoc = Document & {
  startViewTransition?: (cb: () => void) => { ready: Promise<void>; finished: Promise<void> };
};

/**
 * Changes the theme. With `origin` (a click point) the new theme spreads from
 * it as a growing circle (View Transitions); elsewhere colours cross-fade.
 */
export function setTheme(next: 'light' | 'dark', origin?: { x: number; y: number }) {
  if (next === theme.get()) return;
  try {
    localStorage.setItem('ezhik-theme', next);
  } catch {
    /* private mode: the choice lasts for this session */
  }
  const root = document.documentElement;
  const paint = () => {
    root.dataset.theme = next;
    theme.set(next);
  };
  const doc = document as ViewTransitionDoc;
  const still = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  if (still) {
    paint();
    return;
  }
  if (origin && doc.startViewTransition) {
    const { x, y } = origin;
    const r = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
    // CSS colour transitions would put the old colours into the new snapshot.
    root.classList.add('is-theme-morph', 'is-theme-switching');
    const done = () => root.classList.remove('is-theme-morph', 'is-theme-switching');
    const vt = doc.startViewTransition(paint);
    vt.ready
      .then(() => {
        root.animate(
          { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${r}px at ${x}px ${y}px)`] },
          { duration: 560, easing: 'cubic-bezier(0.2, 0, 0, 1)', pseudoElement: '::view-transition-new(root)' },
        );
      })
      .catch(done);
    vt.finished.then(done, done);
    return;
  }
  root.classList.add('is-theme-fading');
  paint();
  window.setTimeout(() => root.classList.remove('is-theme-fading'), 420);
}

export function toggleTheme() {
  setTheme(theme.get() === 'dark' ? 'light' : 'dark');
}

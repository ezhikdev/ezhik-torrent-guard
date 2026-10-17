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

export type Toast = { id: number; kind: 'ok' | 'error' | 'info'; text: string };
export const toasts = signal<Toast[]>([]);
let toastId = 0;

export function toast(text: string, kind: Toast['kind'] = 'ok') {
  const item = { id: ++toastId, kind, text };
  toasts.set([...toasts.get(), item]);
  setTimeout(() => toasts.set(toasts.get().filter((t) => t.id !== item.id)), kind === 'error' ? 7000 : 3800);
}

export function toastError(error: unknown) {
  toast(error instanceof Error ? error.message : String(error), 'error');
}

// ------------------------------------------------------------------ theme

export const theme = signal<string>(document.documentElement.dataset.theme || 'dark');

export function toggleTheme() {
  const next = theme.get() === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem('ezhik-theme', next);
  } catch {
    /* private mode */
  }
  theme.set(next);
}

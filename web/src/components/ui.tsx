import type { ComponentChildren, JSX } from 'preact';
import { createPortal } from 'preact/compat';
import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import { navigate, toast, toastError } from '../state';
import { LoadingIndicator } from './expressive';
import { Icon } from './Icon';

// ------------------------------------------------------------------ data

export function useData<T>(loader: () => Promise<T>, deps: unknown[] = [], refreshMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const alive = useRef(true);
  const reload = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const value = await loader();
      if (alive.current) {
        setData(value);
        setError(null);
      }
    } catch (e) {
      if (alive.current) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (alive.current) setLoading(false);
    }
  }, deps);
  useEffect(() => {
    alive.current = true;
    reload();
    let timer: number | undefined;
    if (refreshMs) {
      timer = window.setInterval(() => {
        if (document.visibilityState === 'visible') reload(true);
      }, refreshMs);
    }
    return () => {
      alive.current = false;
      if (timer) clearInterval(timer);
    };
  }, [reload, refreshMs]);
  return { data, error, loading, reload, setData };
}

export function useAction() {
  const [busy, setBusy] = useState<string | null>(null);
  const run = useCallback(async (key: string, fn: () => Promise<unknown>, okText?: string) => {
    setBusy(key);
    try {
      const result = await fn();
      if (okText) toast(okText);
      return result;
    } catch (e) {
      toastError(e);
      return undefined;
    } finally {
      setBusy(null);
    }
  }, []);
  return { busy, run };
}

// ---------------------------------------------------------------- basics

type BtnProps = {
  variant?: 'primary' | 'ghost' | 'soft' | 'plain' | 'danger' | 'danger-soft';
  size?: 'sm' | 'lg';
  icon?: string;
  iconRight?: string;
  loading?: boolean;
  block?: boolean;
  children?: ComponentChildren;
} & Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, 'size' | 'icon' | 'loading'>;

export function Button({ variant = 'ghost', size, icon, iconRight, loading, block, children, class: cls, disabled, ...rest }: BtnProps) {
  return (
    <button
      type="button"
      {...rest}
      disabled={disabled || loading}
      class={`btn btn--${variant} ${size ? `btn--${size}` : ''} ${block ? 'btn--block' : ''} ${loading ? 'is-loading' : ''} ${cls ?? ''}`}
    >
      {icon && <Icon name={icon} size={size === 'sm' ? 15 : 17} />}
      {children != null && <span>{children}</span>}
      {iconRight && <Icon name={iconRight} size={size === 'sm' ? 15 : 17} />}
      {loading && <span class="btn__spinner" />}
    </button>
  );
}

export function IconButton({ icon, title, onClick, danger, spinning, size, disabled }: {
  icon: string; title: string; onClick?: (e: MouseEvent) => void; danger?: boolean; spinning?: boolean; size?: 'sm'; disabled?: boolean;
}) {
  return (
    <button
      type="button"
      class={`icon-btn ${danger ? 'icon-btn--danger' : ''} ${spinning ? 'is-spinning' : ''} ${size ? 'icon-btn--sm' : ''}`}
      title={title}
      aria-label={title}
      onClick={onClick}
      disabled={disabled}
    >
      <Icon name={icon} size={size ? 15 : 17} />
    </button>
  );
}

export function Badge({ tone, children, dot, size }: { tone?: string; children: ComponentChildren; dot?: boolean; size?: 'sm' }) {
  return (
    <span class={`badge ${tone ? `badge--${tone}` : ''} ${size ? 'badge--sm' : ''}`}>
      {dot && <span class="dot" />}
      {children}
    </span>
  );
}

export function StatusDot({ state }: { state: 'ok' | 'bad' | 'warn' | 'idle' }) {
  return <span class={`dot dot--${state} ${state === 'ok' ? 'dot--pulse' : ''}`} />;
}

export function Switch({ on, onChange, disabled, label }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={disabled}
      class={`switch ${on ? 'is-on' : ''}`}
      onClick={(e) => {
        e.stopPropagation();
        onChange(!on);
      }}
    >
      <span class="switch__thumb">
        <Icon name={on ? 'check' : 'x'} size={14} stroke={2.4} />
      </span>
    </button>
  );
}

export function ToggleRow({ title, desc, on, onChange, disabled, extra }: {
  title: ComponentChildren; desc?: ComponentChildren; on: boolean; onChange: (v: boolean) => void; disabled?: boolean; extra?: ComponentChildren;
}) {
  return (
    <div class="toggle-row">
      <div class="toggle-row__text">
        <div class="toggle-row__title">{title}</div>
        {desc && <div class="toggle-row__desc">{desc}</div>}
      </div>
      {extra}
      <Switch on={on} onChange={onChange} disabled={disabled} />
    </div>
  );
}

export function Segmented<T extends string>({ value, options, onChange }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void }) {
  return (
    <div class="segmented" role="tablist">
      {options.map((o) => (
        <button type="button" key={o.value} class={`segmented__item ${o.value === value ? 'is-active' : ''}`} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Tabs<T extends string>({ value, tabs, onChange }: { value: T; tabs: { value: T; label: string; icon?: string }[]; onChange: (v: T) => void }) {
  return (
    <div class="tabs">
      {tabs.map((t) => (
        <button type="button" key={t.value} class={`tab ${t.value === value ? 'is-active' : ''}`} onClick={() => onChange(t.value)}>
          {t.icon && <Icon name={t.icon} size={16} />}
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Field({ label, hint, error, children }: { label?: ComponentChildren; hint?: ComponentChildren; error?: string | null; children: ComponentChildren }) {
  return (
    <label class="field">
      {label && <span class="field__label">{label}</span>}
      {children}
      {error ? <span class="field__error">{error}</span> : hint ? <span class="field__hint">{hint}</span> : null}
    </label>
  );
}

export function Spinner({ large }: { large?: boolean }) {
  return <span class={`spinner ${large ? 'spinner--lg' : ''}`} />;
}

export function Loading() {
  return (
    <div class="center-screen">
      <LoadingIndicator size={56} />
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div class="card">
      <div class="empty">
        <div class="empty__icon empty__icon--bad">
          <Icon name="alert" size={24} />
        </div>
        <div class="empty__title">Не удалось загрузить данные</div>
        <div class="small">{error}</div>
        {onRetry && <Button icon="refresh" onClick={onRetry}>Повторить</Button>}
      </div>
    </div>
  );
}

export function Empty({ icon, title, children, action }: { icon: string; title: string; children?: ComponentChildren; action?: ComponentChildren }) {
  return (
    <div class="empty">
      <div class="empty__icon">
        <Icon name={icon} size={24} />
      </div>
      <div class="empty__title">{title}</div>
      {children && <div class="small" style={{ maxWidth: '460px' }}>{children}</div>}
      {action}
    </div>
  );
}

export function Callout({ tone, icon, children }: { tone?: 'warn' | 'bad' | 'ok'; icon?: string; children: ComponentChildren }) {
  return (
    <div class={`callout ${tone ? `callout--${tone}` : ''}`}>
      <Icon name={icon ?? (tone === 'bad' ? 'alert' : tone === 'ok' ? 'check' : 'info')} size={17} />
      <div>{children}</div>
    </div>
  );
}

export function copyText(text: string) {
  const done = () => toast('Скопировано');
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
  } else {
    fallbackCopy(text, done);
  }
}

function fallbackCopy(text: string, done: () => void) {
  const area = document.createElement('textarea');
  area.value = text;
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  try {
    document.execCommand('copy');
    done();
  } catch {
    toast('Не удалось скопировать', 'error');
  }
  area.remove();
}

export function CodeBox({ text, copy = true }: { text: string; copy?: boolean }) {
  return (
    <div class="codebox">
      <pre>{text}</pre>
      {copy && <IconButton icon="copy" title="Копировать" size="sm" onClick={() => copyText(text)} />}
    </div>
  );
}

export function Meter({ value, max = 100 }: { value?: number | null; max?: number }) {
  const pct = value == null ? 0 : Math.max(0, Math.min(100, (value / max) * 100));
  const tone = pct > 90 ? 'bad' : pct > 75 ? 'warn' : '';
  return (
    <div class="meter">
      <div class={`meter__fill ${tone ? `meter__fill--${tone}` : ''}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

// ---------------------------------------------------------------- overlays

export function Modal({ title, desc, onClose, children, wide }: { title: ComponentChildren; desc?: ComponentChildren; onClose: () => void; children: ComponentChildren; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
    };
  }, [onClose]);
  // Portal to <body>: a modal opened from inside an animated/transformed card
  // would otherwise be positioned and layered within that card.
  return createPortal(
    <div class="modal-root" role="dialog" aria-modal="true">
      <div class="modal-scrim" onClick={onClose} />
      <div class={`modal ${wide ? 'modal--wide' : ''}`}>
        <div class="modal__head">
          <div>
            <div class="modal__title">{title}</div>
            {desc && <div class="modal__desc">{desc}</div>}
          </div>
          <IconButton icon="x" title="Закрыть" size="sm" onClick={onClose} />
        </div>
        {children}
      </div>
    </div>,
    document.body,
  );
}

type ConfirmOptions = { title: string; text?: ComponentChildren; confirm?: string; danger?: boolean };
let confirmHost: ((o: ConfirmOptions & { resolve: (v: boolean) => void }) => void) | null = null;

export function confirmDialog(options: ConfirmOptions): Promise<boolean> {
  return new Promise((resolve) => {
    if (!confirmHost) resolve(window.confirm(options.title));
    else confirmHost({ ...options, resolve });
  });
}

export function ConfirmHost() {
  const [state, setState] = useState<(ConfirmOptions & { resolve: (v: boolean) => void }) | null>(null);
  useEffect(() => {
    confirmHost = setState;
    return () => {
      confirmHost = null;
    };
  }, []);
  if (!state) return null;
  const close = (value: boolean) => {
    state.resolve(value);
    setState(null);
  };
  return (
    <Modal title={state.title} onClose={() => close(false)}>
      {state.text && <div class="muted" style={{ marginBottom: '6px' }}>{state.text}</div>}
      <div class="form-actions">
        <Button variant="plain" onClick={() => close(false)}>Отмена</Button>
        <Button variant={state.danger ? 'danger' : 'primary'} onClick={() => close(true)}>{state.confirm ?? 'Подтвердить'}</Button>
      </div>
    </Modal>
  );
}

export function Menu({ items, icon = 'more' }: { icon?: string; items: ({ label: string; icon?: string; onClick: () => void; danger?: boolean } | 'sep')[] }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);
  return (
    <div class="menu-wrap" ref={ref} onClick={(e) => e.stopPropagation()}>
      <IconButton icon={icon} title="Действия" size="sm" onClick={() => setOpen(!open)} />
      {open && (
        <div class="menu">
          {items.map((item, i) =>
            item === 'sep' ? (
              <div class="menu__sep" key={i} />
            ) : (
              <button
                type="button"
                key={i}
                class={`menu__item ${item.danger ? 'menu__item--danger' : ''}`}
                onClick={() => {
                  setOpen(false);
                  item.onClick();
                }}
              >
                {item.icon && <Icon name={item.icon} size={16} />}
                {item.label}
              </button>
            ),
          )}
        </div>
      )}
    </div>
  );
}

export function Link({ to, children, class: cls }: { to: string; children: ComponentChildren; class?: string }) {
  return (
    <a
      href={to}
      class={cls}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.button !== 0) return;
        e.preventDefault();
        navigate(to);
      }}
    >
      {children}
    </a>
  );
}

export function PageHead({ title, sub, actions, crumbs }: { title: ComponentChildren; sub?: ComponentChildren; actions?: ComponentChildren; crumbs?: { label: string; to?: string }[] }) {
  return (
    <>
      {crumbs && (
        <div class="crumbs">
          {crumbs.map((c, i) => (
            <span class="row" style={{ gap: '6px' }} key={i}>
              {c.to ? <Link to={c.to}>{c.label}</Link> : <span>{c.label}</span>}
              {i < crumbs.length - 1 && <Icon name="chevronRight" size={13} />}
            </span>
          ))}
        </div>
      )}
      <div class="page-head">
        <div>
          <h1 class="page-title">{title}</h1>
          {sub && <div class="page-sub">{sub}</div>}
        </div>
        {actions && <div class="row row--wrap">{actions}</div>}
      </div>
    </>
  );
}

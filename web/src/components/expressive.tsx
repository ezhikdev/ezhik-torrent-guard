/**
 * Expressive primitives shared with the Ezhik VPN WebApp: soft polar shapes
 * (cookie / burst / clover), the shape-morphing loading indicator and the
 * sun/moon theme toggle.
 */
import { useMemo, useRef } from 'preact/hooks';
import { prefersReducedMotion } from '../motion';
import { setTheme, theme, useSignal } from '../state';

/** Closed polar shape in a 0..1 box: k soft lobes of relative depth a. */
function polar(k: number, a: number, rotate = 0, n = 120): string {
  let d = '';
  for (let i = 0; i < n; i++) {
    const t = (i / n) * Math.PI * 2;
    const r = (0.5 * (1 + a * Math.cos(k * (t + rotate)))) / (1 + a);
    d += `${i ? 'L' : 'M'}${(0.5 + r * Math.sin(t)).toFixed(4)},${(0.5 - r * Math.cos(t)).toFixed(4)}`;
  }
  return `${d}Z`;
}

export const SHAPES = {
  cookie12: polar(12, 0.045),
  cookie9: polar(9, 0.065),
  burst: polar(10, 0.085),
  clover: polar(4, 0.11, Math.PI / 4),
  pentagon: polar(5, 0.09),
};

/** The loader cycles through these (all with the same point count, so they morph). */
const LOADER = [polar(10, 0.085), polar(9, 0.065), polar(5, 0.1), polar(2, 0.15), polar(8, 0.05), polar(4, 0.11)];

/** clipPath definitions referenced from CSS as url(#shape-…). Render once per page. */
export function ShapeDefs() {
  return (
    <svg class="shape-defs" width="0" height="0" aria-hidden="true" focusable="false">
      <defs>
        {Object.entries(SHAPES).map(([id, d]) => (
          <clipPath key={id} id={`shape-${id}`} clipPathUnits="objectBoundingBox">
            <path d={d} />
          </clipPath>
        ))}
      </defs>
    </svg>
  );
}

/** Decorative filled shape (animated from CSS). */
export function Blob({ shape = 'cookie9', class: cls = '' }: { shape?: keyof typeof SHAPES; class?: string }) {
  return (
    <svg class={`blob ${cls}`} viewBox="0 0 1 1" aria-hidden="true" focusable="false">
      <path d={SHAPES[shape]} />
    </svg>
  );
}

/** Indeterminate loader: a soft shape that morphs and turns (SMIL). */
export function LoadingIndicator({ size = 48, contained, label = 'Загрузка' }: { size?: number; contained?: boolean; label?: string }) {
  const still = prefersReducedMotion();
  const values = [...LOADER, LOADER[0]].join(';');
  const times = LOADER.map((_, i) => (i / LOADER.length).toFixed(4)).concat('1').join(';');
  const splines = LOADER.map(() => '0.45 0 0.1 1').join(';');
  return (
    <span class={`loader ${contained ? 'loader--contained' : ''}`} style={{ width: `${size}px`, height: `${size}px` }} role="progressbar" aria-label={label}>
      <svg viewBox="0 0 1 1" class="loader__shape" focusable="false">
        <path d={LOADER[0]}>
          {!still && (
            <animate attributeName="d" values={values} keyTimes={times} keySplines={splines} calcMode="spline"
              dur={`${LOADER.length * 0.7}s`} repeatCount="indefinite" />
          )}
        </path>
      </svg>
    </span>
  );
}

let maskSeq = 0;

/** Sun that turns into a crescent moon. */
export function SunMoon({ dark, size = 20 }: { dark: boolean; size?: number }) {
  const id = useMemo(() => `sm-${++maskSeq}`, []);
  return (
    <svg class={`sunmoon ${dark ? 'is-dark' : ''}`} width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <mask id={id}>
        <rect width="24" height="24" fill="#fff" />
        <circle class="sunmoon__bite" cx="17" cy="7" r="6" fill="#000" />
      </mask>
      <circle class="sunmoon__core" cx="12" cy="12" r="5.5" fill="currentColor" mask={`url(#${id})`} />
      <g class="sunmoon__rays" stroke="currentColor" stroke-width="1.9" stroke-linecap="round">
        {[0, 45, 90, 135, 180, 225, 270, 315].map((a) => (
          <line key={a} x1="12" y1="1.8" x2="12" y2="3.6" transform={`rotate(${a} 12 12)`} />
        ))}
      </g>
    </svg>
  );
}

/** Light/dark switch; the new theme spreads from the button as a circle. */
export function ThemeToggle({ class: cls = '', withLabel }: { class?: string; withLabel?: boolean }) {
  const current = useSignal(theme);
  const ref = useRef<HTMLButtonElement>(null);
  const dark = current === 'dark';
  return (
    <button
      ref={ref}
      type="button"
      class={`theme-toggle ${withLabel ? 'theme-toggle--label' : 'icon-btn'} ${cls}`}
      aria-label={dark ? 'Светлая тема' : 'Тёмная тема'}
      title={dark ? 'Светлая тема' : 'Тёмная тема'}
      onClick={() => {
        const r = ref.current?.getBoundingClientRect();
        setTheme(dark ? 'light' : 'dark', r ? { x: r.left + r.width / 2, y: r.top + r.height / 2 } : undefined);
      }}
    >
      <SunMoon dark={dark} />
      {withLabel && <span>{dark ? 'Тёмная тема' : 'Светлая тема'}</span>}
    </button>
  );
}

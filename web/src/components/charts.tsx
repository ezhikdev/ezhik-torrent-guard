import type { ComponentChildren } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';

export type Series = { key: string; label: string; color: string };

function useWidth() {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  useEffect(() => {
    if (!ref.current) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(200, entry.contentRect.width)));
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);
  return { ref, width };
}

function niceMax(value: number) {
  if (value <= 4) return 4;
  const pow = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 2.5, 5, 10]) {
    if (step * pow >= value) return step * pow;
  }
  return 10 * pow;
}

export function Legend({ series }: { series: Series[] }) {
  return (
    <div class="legend">
      {series.map((s) => (
        <span class="legend__item" key={s.key}>
          <span class="legend__swatch" style={{ background: s.color }} />
          {s.label}
        </span>
      ))}
    </div>
  );
}

/** Stacked bars per time bucket; per-bucket hover tooltip. */
export function StackedBars({ buckets, series, height = 220, formatX, empty }: {
  buckets: { ts: number; values: Record<string, number> }[];
  series: Series[];
  height?: number;
  formatX: (ts: number) => string;
  empty?: ComponentChildren;
}) {
  const { ref, width } = useWidth();
  const [hover, setHover] = useState<number | null>(null);
  const pad = { l: 34, r: 6, t: 8, b: 22 };
  const totals = buckets.map((b) => series.reduce((sum, s) => sum + (b.values[s.key] || 0), 0));
  const max = niceMax(Math.max(0, ...totals));
  const plotW = width - pad.l - pad.r;
  const plotH = height - pad.t - pad.b;
  const slot = plotW / Math.max(1, buckets.length);
  const barW = Math.max(2, Math.min(28, slot - 2));
  const y = (v: number) => pad.t + plotH - (v / max) * plotH;
  const ticks = [0, max / 2, max];
  const labelEvery = Math.ceil(buckets.length / Math.max(2, Math.floor(plotW / 70)));
  const allZero = totals.every((t) => t === 0);

  return (
    <div class="chart" ref={ref} onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${width} ${height}`} height={height} role="img" aria-label="События по времени">
        <g class="chart__grid">
          {ticks.map((t) => (
            <line key={t} x1={pad.l} x2={width - pad.r} y1={y(t)} y2={y(t)} />
          ))}
        </g>
        <g class="chart__axis">
          {ticks.map((t) => (
            <text key={t} x={pad.l - 8} y={y(t) + 3} text-anchor="end">{Math.round(t)}</text>
          ))}
          {buckets.map((b, i) =>
            i % labelEvery === 0 ? (
              <text key={b.ts} x={pad.l + slot * i + slot / 2} y={height - 5} text-anchor="middle">{formatX(b.ts)}</text>
            ) : null,
          )}
        </g>
        {buckets.map((b, i) => {
          let acc = 0;
          const x = pad.l + slot * i + (slot - barW) / 2;
          const segments = series.filter((s) => (b.values[s.key] || 0) > 0);
          return (
            <g key={b.ts} opacity={hover == null || hover === i ? 1 : 0.45}>
              {segments.map((s, j) => {
                const v = b.values[s.key];
                const top = y(acc + v);
                const bottom = y(acc);
                acc += v;
                // 2px surface gap between stacked segments; rounded data-end on top only.
                const h = Math.max(1, bottom - top - (j > 0 ? 2 : 0));
                const isTop = j === segments.length - 1;
                const r = isTop ? Math.min(4, barW / 2, h) : 0;
                return (
                  <path
                    key={s.key}
                    fill={s.color}
                    d={`M${x},${top + h} V${top + r} Q${x},${top} ${x + r},${top} H${x + barW - r} Q${x + barW},${top} ${x + barW},${top + r} V${top + h} Z`}
                  />
                );
              })}
              <rect x={pad.l + slot * i} y={pad.t} width={slot} height={plotH} fill="transparent" onMouseEnter={() => setHover(i)} />
            </g>
          );
        })}
      </svg>
      {allZero && empty && <div class="chart-empty">{empty}</div>}
      {hover != null && buckets[hover] && (
        <div class="chart__tip" style={{ left: `${Math.min(width - 90, Math.max(90, pad.l + slot * hover + slot / 2))}px` }}>
          <div class="faint tiny" style={{ marginBottom: '4px' }}>{formatX(buckets[hover].ts)}</div>
          {series.map((s) => (
            <div class="row" style={{ gap: '7px' }} key={s.key}>
              <span class="legend__swatch" style={{ background: s.color }} />
              <span class="grow">{s.label}</span>
              <b class="num">{buckets[hover].values[s.key] || 0}</b>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Line chart with a shared y scale, crosshair and tooltip. */
export function LineChart({ points, series, height = 200, formatY, formatX, max: fixedMax }: {
  points: { ts: number; [key: string]: number }[];
  series: Series[];
  height?: number;
  formatY: (v: number) => string;
  formatX: (ts: number) => string;
  max?: number;
}) {
  const { ref, width } = useWidth();
  const [hover, setHover] = useState<number | null>(null);
  const pad = { l: 52, r: 8, t: 8, b: 22 };
  const plotW = width - pad.l - pad.r;
  const plotH = height - pad.t - pad.b;
  if (points.length < 2) {
    return <div class="chart-empty" style={{ height: `${height}px` }}>Недостаточно данных — метрики появятся через пару минут</div>;
  }
  const max = fixedMax ?? niceMax(Math.max(1, ...points.flatMap((p) => series.map((s) => p[s.key] || 0))));
  const t0 = points[0].ts;
  const t1 = points[points.length - 1].ts;
  const x = (ts: number) => pad.l + ((ts - t0) / Math.max(1, t1 - t0)) * plotW;
  const y = (v: number) => pad.t + plotH - (Math.min(v, max) / max) * plotH;
  const ticks = [0, max / 2, max];
  const xTicks = 5;

  const onMove = (e: MouseEvent) => {
    const rect = (e.currentTarget as SVGElement).getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * width;
    const ts = t0 + ((px - pad.l) / plotW) * (t1 - t0);
    let best = 0;
    points.forEach((p, i) => {
      if (Math.abs(p.ts - ts) < Math.abs(points[best].ts - ts)) best = i;
    });
    setHover(best);
  };

  return (
    <div class="chart" ref={ref}>
      <svg viewBox={`0 0 ${width} ${height}`} height={height} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        <g class="chart__grid">
          {ticks.map((t) => (
            <line key={t} x1={pad.l} x2={width - pad.r} y1={y(t)} y2={y(t)} />
          ))}
        </g>
        <g class="chart__axis">
          {ticks.map((t) => (
            <text key={t} x={pad.l - 8} y={y(t) + 3} text-anchor="end">{formatY(t)}</text>
          ))}
          {Array.from({ length: xTicks }, (_, i) => t0 + ((t1 - t0) * i) / (xTicks - 1)).map((ts, i) => (
            <text key={i} x={x(ts)} y={height - 5} text-anchor={i === 0 ? 'start' : i === xTicks - 1 ? 'end' : 'middle'}>{formatX(ts)}</text>
          ))}
        </g>
        {series.map((s) => {
          const d = points.map((p, i) => `${i ? 'L' : 'M'}${x(p.ts).toFixed(1)},${y(p[s.key] || 0).toFixed(1)}`).join(' ');
          return <path key={s.key} d={d} fill="none" stroke={s.color} stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />;
        })}
        {hover != null && (
          <g>
            <line x1={x(points[hover].ts)} x2={x(points[hover].ts)} y1={pad.t} y2={pad.t + plotH} stroke="var(--line-2)" />
            {series.map((s) => (
              <circle key={s.key} cx={x(points[hover].ts)} cy={y(points[hover][s.key] || 0)} r="4.5" fill={s.color} stroke="var(--card)" stroke-width="2" />
            ))}
          </g>
        )}
      </svg>
      {hover != null && (
        <div class="chart__tip" style={{ left: `${Math.min(width - 90, Math.max(90, x(points[hover].ts)))}px` }}>
          <div class="faint tiny" style={{ marginBottom: '4px' }}>{formatX(points[hover].ts)}</div>
          {series.map((s) => (
            <div class="row" style={{ gap: '7px' }} key={s.key}>
              <span class="legend__swatch" style={{ background: s.color }} />
              <span class="grow">{s.label}</span>
              <b class="num">{formatY(points[hover][s.key] || 0)}</b>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function UptimeStrip({ hours }: { hours: { hour: number; value: number | null }[] }) {
  return (
    <div class="uptime-strip" role="img" aria-label="Доступность по часам">
      {hours.map((h) => {
        const cls = h.value == null ? '' : h.value >= 0.99 ? 'u-ok' : h.value > 0.5 ? 'u-part' : 'u-bad';
        const label = h.value == null ? 'нет данных' : `${Math.round(h.value * 100)}%`;
        return <span key={h.hour} class={cls} title={`${new Date(h.hour * 1000).toLocaleString('ru-RU', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })}: ${label}`} />;
      })}
    </div>
  );
}

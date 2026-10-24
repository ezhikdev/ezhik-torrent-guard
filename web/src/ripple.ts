/**
 * Touch ripple from the exact press point, for every pressable surface
 * (same as the Ezhik VPN WebApp). One delegated listener; each press adds a
 * single span animated with transform/opacity only, removed once it fades.
 */
import { prefersReducedMotion } from './motion';

const TARGETS = [
  '.btn',
  '.icon-btn',
  '.nav-item',
  '.card--interactive',
  '.segmented__item',
  '.tab',
  '.menu__item',
  '.filter-chip',
  '.node-mini',
  '.theme-toggle',
].join(',');

export function installRipple() {
  if (typeof document === 'undefined' || !('animate' in Element.prototype)) return;
  document.addEventListener(
    'pointerdown',
    (e) => {
      if (e.button !== 0 || prefersReducedMotion()) return;
      const host = (e.target as Element | null)?.closest?.(TARGETS) as HTMLElement | null;
      if (!host || (host as HTMLButtonElement).disabled || host.classList.contains('no-ripple')) return;
      const rect = host.getBoundingClientRect();
      const zoom = host.offsetWidth ? rect.width / host.offsetWidth : 1;
      const x = (e.clientX - rect.left) / zoom;
      const y = (e.clientY - rect.top) / zoom;
      const w = host.offsetWidth;
      const h = host.offsetHeight;
      const radius = Math.hypot(Math.max(x, w - x), Math.max(y, h - y));
      const dot = document.createElement('span');
      dot.className = 'ripple';
      dot.style.left = `${x - radius}px`;
      dot.style.top = `${y - radius}px`;
      dot.style.width = dot.style.height = `${radius * 2}px`;
      host.appendChild(dot);
      const grow = dot.animate([{ transform: 'scale(0.12)', opacity: 0.55 }, { transform: 'scale(1)', opacity: 1 }], {
        duration: Math.min(560, 260 + radius * 0.9),
        easing: 'cubic-bezier(0.2, 0, 0, 1)',
        fill: 'forwards',
      });
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        window.removeEventListener('pointerup', release);
        window.removeEventListener('pointercancel', release);
        const fade = () =>
          (dot.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 280, easing: 'linear', fill: 'forwards' }).onfinish = () =>
            dot.remove());
        // A quick tap still shows most of the wave before it fades.
        if (grow.playState === 'finished') fade();
        else window.setTimeout(fade, 120);
      };
      window.addEventListener('pointerup', release);
      window.addEventListener('pointercancel', release);
    },
    { passive: true },
  );
}

/**
 * Motion layer (shared with the Ezhik VPN WebApp): spring curves for the Web
 * Animations API, a resize guard and the "liquid" stretch of sliding
 * indicators. Only transform/opacity are animated; everything is skipped for
 * prefers-reduced-motion.
 */
import type { RefObject } from 'preact';
import { useLayoutEffect, useRef } from 'preact/hooks';

export const prefersReducedMotion = () =>
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

/** Fast start, long soft landing (out-quint). */
export const EASE_OUT = 'cubic-bezier(0.22, 1, 0.36, 1)';

/* Damped springs sampled for CSS linear() — the same curves as --spring and
   --spring-bouncy in base.css (ζ0.8 k380 and ζ0.6 k800). */
const SPRING_LINEAR =
  'linear(0, 0.023 2.5%, 0.081 5.0%, 0.160 7.5%, 0.251 10.0%, 0.345 12.5%, 0.439 15.0%, 0.528 17.5%, 0.610 20.0%, ' +
  '0.681 22.5%, 0.746 25.0%, 0.802 27.5%, 0.849 30.0%, 0.889 32.5%, 0.921 35.0%, 0.947 37.5%, 0.967 40.0%, 0.982 42.5%, ' +
  '0.994 45.0%, 1.002 47.5%, 1.008 50.0%, 1.011 52.5%, 1.014 55.0%, 1.014 60.0%, 1.013 65.0%, 1.010 70.0%, 1.008 75.0%, ' +
  '1.005 80.0%, 1.003 85.0%, 1.002 90.0%, 1.001 95.0%, 1)';
const BOUNCY_LINEAR =
  'linear(0, 0.038 2.5%, 0.130 5.0%, 0.254 7.5%, 0.386 10.0%, 0.526 12.5%, 0.658 15.0%, 0.769 17.5%, 0.868 20.0%, ' +
  '0.948 22.5%, 1.005 25.0%, 1.048 27.5%, 1.075 30.0%, 1.089 32.5%, 1.093 35.0%, 1.090 37.5%, 1.082 40.0%, 1.071 42.5%, ' +
  '1.058 45.0%, 1.046 47.5%, 1.033 50.0%, 1.022 52.5%, 1.013 55.0%, 1.006 57.5%, 1.000 60.0%, 0.996 62.5%, 0.993 65.0%, ' +
  '0.991 70.0%, 0.992 75.0%, 0.994 80.0%, 0.997 85.0%, 0.999 90.0%, 1)';

const supportsLinear = typeof CSS !== 'undefined' && CSS.supports?.('transition-timing-function', 'linear(0, 1)');
export const SPRING = supportsLinear ? SPRING_LINEAR : EASE_OUT;
export const SPRING_BOUNCY = supportsLinear ? BOUNCY_LINEAR : EASE_OUT;

const supportsScale = typeof CSS !== 'undefined' && CSS.supports?.('scale', '1');

/* While the window is being resized layout changes are not user actions:
   animating them would make the whole UI wobble. */
let resizing = false;
if (typeof window !== 'undefined') {
  let timer = 0;
  window.addEventListener(
    'resize',
    () => {
      resizing = true;
      document.documentElement.classList.add('is-resizing');
      clearTimeout(timer);
      timer = window.setTimeout(() => {
        resizing = false;
        document.documentElement.classList.remove('is-resizing');
      }, 220);
    },
    { passive: true },
  );
}

export const canAnimate = () =>
  !resizing && typeof Element !== 'undefined' && 'animate' in Element.prototype && !prefersReducedMotion();

/**
 * A sliding indicator stretches along its path and springs back, like a drop
 * of liquid. `key` is whatever identifies the current position; `distance`
 * how far it travels (in item steps).
 */
export function useThumbStretch<T extends HTMLElement>(ref: RefObject<T>, key: string | number, distance = 1, vertical = false) {
  const prev = useRef(key);
  useLayoutEffect(() => {
    const from = prev.current;
    prev.current = key;
    const el = ref.current;
    if (!el || from === key || !canAnimate() || !supportsScale) return;
    const k = 1 + Math.min(0.32, 0.12 * Math.max(1, Math.abs(distance)));
    const mid = vertical ? `0.97 ${k}` : `${k} 0.9`;
    // `scale` is independent of the `translate` transition that slides it.
    el.animate([{ scale: '1 1' }, { scale: mid, offset: 0.3 }, { scale: '1 1' }], { duration: 520, easing: SPRING_BOUNCY });
  }, [key]);
}

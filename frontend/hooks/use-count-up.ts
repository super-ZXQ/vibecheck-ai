/**
 * useCountUp — smooth numeric count-up animation.
 *
 * Animates from the previous target to the new target using
 * requestAnimationFrame with an ease-out curve. Respects
 * prefers-reduced-motion by jumping straight to the target.
 */

"use client";

import { useEffect, useRef, useState } from "react";

export function useCountUp(target: number, durationMs = 700): number {
  const [value, setValue] = useState(0);
  const prevTargetRef = useRef(0);

  useEffect(() => {
    const from = prevTargetRef.current;
    prevTargetRef.current = target;
    if (from === target) {
      setValue(target);
      return;
    }

    const prefersReducedMotion =
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion) {
      setValue(target);
      return;
    }

    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / durationMs);
      const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
      setValue(Math.round(from + (target - from) * eased));
      if (progress < 1) {
        raf = requestAnimationFrame(tick);
      }
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs]);

  return value;
}

import { cn } from '../lib/cn'

/**
 * The spine — a 3px rule on the leading edge.
 *
 * The one signature element: it marks the active nav item, the current tab
 * and the active app in the switcher. Status tones exist for rows that carry
 * a state (a failed upload, a revoked session). Classes are written out in
 * full because Tailwind reads source text; an interpolated class compiles to
 * nothing.
 *
 * Renders inside a `relative` parent and is `aria-hidden`: whatever it marks
 * is always also said in text.
 */
export type SpineTone = 'brand' | 'chrome' | 'ok' | 'warn' | 'danger' | 'none'

function toneClasses(tone: SpineTone): string {
  switch (tone) {
    case 'brand':
      return 'bg-primary'
    case 'chrome':
      return 'bg-chrome-active'
    case 'ok':
      return 'bg-status-ok'
    case 'warn':
      return 'bg-status-warn'
    case 'danger':
      return 'bg-status-danger'
    case 'none':
      return 'bg-transparent'
  }
}

export function Spine({ tone, className }: { tone: SpineTone; className?: string }) {
  return (
    <span
      aria-hidden
      className={cn('absolute inset-y-1 left-0 w-[3px] rounded-full', toneClasses(tone), className)}
    />
  )
}

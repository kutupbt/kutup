import { cn } from '../lib/cn'

// The three-diamond mark is a Kutup brand asset — see /TRADEMARK.md. The
// AGPL-3.0 covering this code grants no rights to the artwork, and the mark
// must not be recoloured or modified; that is why it is fixed hex here and
// not theme tokens.
export function KutupLogo({ size = 28, className }: { size?: number; className?: string }) {
  const scale = size / 44
  return (
    <svg
      width={56 * scale}
      height={44 * scale}
      viewBox="0 0 56 44"
      fill="none"
      aria-hidden
      className={className}
    >
      <polygon points="10,13 16,22 10,31 4,22" fill="#0369a1" />
      <polygon points="28,8 37,22 28,36 19,22" fill="#38bdf8" />
      <polygon points="46,11 53,22 46,33 39,22" fill="#7dd3fc" />
    </svg>
  )
}

/** Logo + "Kutup" + the app name ("Drive"), for the chrome's top-left corner. */
export function BrandLockup({ app, className }: { app?: string; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-2', className)}>
      <KutupLogo size={22} />
      <span className="font-display text-lg font-semibold tracking-tight">Kutup</span>
      {app ? <span className="text-lg text-chrome-muted">{app}</span> : null}
    </span>
  )
}

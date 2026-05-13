// The three-diamond mark drawn here is a kutup brand asset — see
// /TRADEMARK.md for the brand-use policy. The AGPL-3.0 that covers
// the surrounding code does not grant rights to the artwork itself.
export function KutupLogo({ size = 36 }: { size?: number }) {
  const scale = size / 44
  return (
    <svg width={56 * scale} height={44 * scale} viewBox="0 0 56 44" fill="none">
      {/* Left — small, deep blue */}
      <polygon points="10,13 16,22 10,31 4,22" fill="#0369a1" />
      {/* Center — large, bright glacier */}
      <polygon points="28,8 37,22 28,36 19,22" fill="#38bdf8" />
      {/* Right — medium, pale ice */}
      <polygon points="46,11 53,22 46,33 39,22" fill="#7dd3fc" />
    </svg>
  )
}

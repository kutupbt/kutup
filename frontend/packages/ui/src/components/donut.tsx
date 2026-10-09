import type { ReactNode } from 'react'
import { cn } from '../lib/cn'

/** One arc: its share of the whole (0–100) and a CSS colour, usually a token. */
export type DonutSegment = [percentage: number, color: string]

/**
 * A ring chart, after Proton's `Donut` atom: segments run clockwise from the
 * top, and what they leave of 100 is drawn in a neutral track. Segments that
 * add up to more than 100 are scaled down to fit. `children` sit in the hole.
 * Decorative: give the figures in text beside it.
 */
export function Donut({
  segments,
  gap = 0,
  thickness = 1 / 6,
  minPercent = 0,
  className,
  children,
}: {
  segments: DonutSegment[]
  /** Space between arcs, in viewbox units out of 200. */
  gap?: number
  /** Ring width as a share of the diameter. */
  thickness?: number
  /** Draw every non-empty segment at least this large, so small ones stay visible. */
  minPercent?: number
  className?: string
  children?: ReactNode
}) {
  const box = 200
  const width = box * thickness
  const radius = box / 2 - width / 2
  const circumference = 2 * Math.PI * radius
  const visible = segments.filter(([p]) => p > 0).map(([p, color]): DonutSegment => [Math.max(p, minPercent), color])
  const sum = visible.reduce((total, [p]) => total + p, 0)
  const scale = sum > 100 ? 100 / sum : 1
  let start = 0
  const arcs = visible.map(([p, color]) => {
    const length = (p * scale * circumference) / 100
    const arc = { color, offset: start, length: Math.max(0, length - (visible.length > 1 ? gap : 0)) }
    start += length
    return arc
  })
  return (
    <div className={cn('relative inline-grid place-items-center', className)}>
      <svg viewBox={`0 0 ${box} ${box}`} className="size-full -rotate-90" aria-hidden>
        <circle cx={box / 2} cy={box / 2} r={radius} fill="none" stroke="var(--muted)" strokeWidth={width} />
        {arcs.map((arc, i) => (
          <circle
            key={i}
            cx={box / 2}
            cy={box / 2}
            r={radius}
            fill="none"
            stroke={arc.color}
            strokeWidth={width}
            strokeDasharray={`${arc.length} ${circumference - arc.length}`}
            strokeDashoffset={-arc.offset}
          />
        ))}
      </svg>
      {children ? <div className="absolute inset-0 grid place-items-center text-center">{children}</div> : null}
    </div>
  )
}

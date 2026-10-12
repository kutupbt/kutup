import { useEffect, useRef, useState } from 'react'
import { cn } from '@kutup/ui/lib/cn'
import { useSiteIcon } from '../sync/siteIcons'

/**
 * An entry's website icon (`sync/siteIcons.ts`), asked for once the row
 * scrolls into view; the title's first letter until then, and when there
 * is none.
 */
export function SiteIcon({ title, address, className }: { title: string; address: string; className?: string }) {
  const box = useRef<HTMLSpanElement>(null)
  const [visible, setVisible] = useState(false)
  const src = useSiteIcon(visible ? address : '')
  const [broken, setBroken] = useState<string | null>(null)

  useEffect(() => {
    const element = box.current
    if (!element || visible) return
    if (typeof IntersectionObserver === 'undefined') {
      setVisible(true)
      return
    }
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) setVisible(true)
    })
    observer.observe(element)
    return () => observer.disconnect()
  }, [visible])

  const showing = src && src !== broken ? src : null
  return (
    <span ref={box} className={cn('grid size-8 shrink-0 place-items-center overflow-hidden rounded-md bg-muted text-xs font-semibold uppercase', className)} aria-hidden>
      {showing ? (
        <img src={showing} alt="" className="size-5 object-contain" onError={() => setBroken(showing)} />
      ) : (
        (title || '?').slice(0, 1)
      )}
    </span>
  )
}

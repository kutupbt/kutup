import { useRef } from 'react'
import { Palette } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { CURSOR_COLORS_20 } from '../../collab/identity'

interface Props {
  color: string
  onChange: (hex: string) => void
}

export default function CursorColorPicker({ color, onChange }: Props) {
  const customRef = useRef<HTMLInputElement>(null)

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          title="Cursor color"
          aria-label="Cursor color"
          className="inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs hover:bg-muted"
        >
          <span
            className="inline-block h-3 w-3 rounded-full border border-border"
            style={{ background: color }}
          />
          <Palette className="h-3 w-3" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
          Cursor color
        </DropdownMenuLabel>
        <div className="grid grid-cols-5 gap-1.5 px-2 py-1.5">
          {CURSOR_COLORS_20.map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => onChange(c)}
              title={c}
              aria-label={`Use ${c}`}
              className="h-6 w-6 rounded-full transition-transform hover:scale-110"
              style={{
                background: c,
                outline: c.toLowerCase() === color.toLowerCase() ? '2px solid var(--ring)' : 'none',
                outlineOffset: 2,
              }}
            />
          ))}
        </div>
        <DropdownMenuSeparator />
        <button
          type="button"
          onClick={() => customRef.current?.click()}
          className="flex w-full items-center gap-2 px-2 py-1.5 text-sm hover:bg-accent"
        >
          <span
            className="inline-block h-4 w-4 rounded border border-border"
            style={{
              background:
                'conic-gradient(from 0deg, red, yellow, lime, cyan, blue, magenta, red)',
            }}
          />
          Custom color…
          <input
            ref={customRef}
            type="color"
            value={color}
            onChange={(e) => onChange(e.target.value)}
            className="sr-only"
          />
        </button>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

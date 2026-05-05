import { useRef } from 'react'
import { Palette } from 'lucide-react'
import { Button } from '@/components/ui/button'
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
        <Button
          type="button"
          size="sm"
          variant="outline"
          title="Cursor color"
          aria-label="Cursor color"
          className="gap-1.5"
        >
          <span
            className="inline-block h-3.5 w-3.5 rounded-full border border-border"
            style={{ background: color }}
            aria-hidden
          />
          <Palette className="h-4 w-4" />
        </Button>
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

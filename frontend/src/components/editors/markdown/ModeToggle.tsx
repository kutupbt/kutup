// Three-segment Edit / Split / Read button group for the notes editor
// header. Mirrors Obsidian's mode-toggle button.

import { Pencil, Columns, BookOpen } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import type { MarkdownMode } from './useMarkdownMode'

interface Props {
  mode: MarkdownMode
  onChange: (m: MarkdownMode) => void
}

export default function ModeToggle({ mode, onChange }: Props) {
  const { t } = useTranslation()
  const items: Array<{ mode: MarkdownMode; Icon: typeof Pencil; labelKey: string }> = [
    { mode: 'edit',  Icon: Pencil,   labelKey: 'notes.mode.edit' },
    { mode: 'split', Icon: Columns,  labelKey: 'notes.mode.split' },
    { mode: 'read',  Icon: BookOpen, labelKey: 'notes.mode.read' },
  ]
  return (
    <div className="inline-flex rounded-md border border-border bg-background">
      {items.map(({ mode: m, Icon, labelKey }) => {
        const active = mode === m
        return (
          <Button
            key={m}
            type="button"
            variant="ghost"
            size="sm"
            className={cn(
              'rounded-none border-r border-border last:border-r-0 first:rounded-l-md last:rounded-r-md',
              'h-8 px-2.5 gap-1.5 text-xs',
              active && 'bg-accent text-accent-foreground',
            )}
            aria-pressed={active}
            title={t(labelKey)}
            onClick={() => onChange(m)}
          >
            <Icon className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">{t(labelKey)}</span>
          </Button>
        )
      })}
    </div>
  )
}

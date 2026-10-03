import { Fragment, useState, type ReactNode } from 'react'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuLabel,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@kutup/ui/components/context-menu'
import type { ExplorerAction } from './Explorer'

export interface ContextMenuSpec {
  /** Shown above the actions, e.g. "3 selected". */
  label?: string
  actions: ExplorerAction[]
}

/**
 * The right-click menu for a Drive list: on an item, its actions (or the
 * whole selection's, when it is part of one); on empty space, what can be
 * made there. Long-press opens it on touch.
 *
 * `menuFor` gets the key of the item under the pointer (from its
 * `data-item-key`), or null for empty space, and may change the selection
 * first — right-clicking an unselected item selects it, as on a desktop.
 * An empty menu falls through to nothing (no browser menu either).
 */
export function ExplorerContextMenu({
  menuFor,
  children,
}: {
  menuFor: (key: string | null) => ContextMenuSpec
  children: ReactNode
}) {
  const [spec, setSpec] = useState<ContextMenuSpec>({ actions: [] })
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <div
          className="flex flex-1 flex-col"
          onContextMenu={(event) => {
            const target = event.target as HTMLElement
            const key = target.closest('[data-item-key]')?.getAttribute('data-item-key') ?? null
            const next = menuFor(key)
            // Suppresses both the browser's menu and ours.
            if (next.actions.length === 0) event.preventDefault()
            setSpec(next)
          }}
        >
          {children}
        </div>
      </ContextMenuTrigger>
      <ContextMenuContent className="w-56">
        {spec.label ? <ContextMenuLabel>{spec.label}</ContextMenuLabel> : null}
        {spec.actions.map((action, i) => (
          <Fragment key={action.id}>
            {action.separated && i > 0 ? <ContextMenuSeparator /> : null}
            <ContextMenuItem destructive={action.destructive} onSelect={action.onSelect}>
              {action.icon}
              {action.label}
            </ContextMenuItem>
          </Fragment>
        ))}
      </ContextMenuContent>
    </ContextMenu>
  )
}

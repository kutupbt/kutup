import { ArchiveRestore, Folder, FolderInput, MoreHorizontal, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { groupTargets } from '../lib/groupMoves'
import type { VaultSession } from '../sync/vaultSession'
import type { GroupView, VaultView } from '../vault/types'

/**
 * The groups in the recycle bin, above its entries
 * (docs/plans/pass-gaps-2.md, P1): each comes back with what it holds to the
 * group it was in (or the top group), moves to another group, or is deleted
 * for good. A read-only vault only lists them.
 */
export function DeletedGroups({ session, view, groups }: { session: VaultSession; view: VaultView; groups: GroupView[] }) {
  const { t } = useTranslation()
  const [deleting, setDeleting] = useState<GroupView | null>(null)
  const editable = session.canEdit
  // Anywhere outside the bin: a deleted group isn't in the tree it moves to.
  const targets = (group: GroupView) => groupTargets(view, { ...group, parentId: null })

  const run = (op: Parameters<VaultSession['apply']>[0], done: string) =>
    void session.apply(op).then(
      () => toast.success(done),
      () => toast.error(t('entry.saveFailed')),
    )

  return (
    <section aria-label={t('groups.deletedGroups')} className="border-b border-border">
      <h2 className="px-3 pt-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">{t('groups.deletedGroups')}</h2>
      <ul className="p-1 text-sm">
        {groups.map((g) => (
          <li key={g.id} className="flex items-center gap-1 rounded-md px-2 py-1 hover:bg-accent/40">
            <Folder className="size-4 shrink-0" aria-hidden />
            <span className="min-w-0 flex-1 truncate">{g.name}</span>
            {editable ? (
              <>
                <Button variant="ghost" size="sm" onClick={() => run({ op: 'restoreGroups', ids: [g.id] }, t('groups.restored', { name: g.name }))}>
                  <ArchiveRestore />
                  {t('groups.restore')}
                </Button>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon" className="size-7" aria-label={t('groups.actions', { name: g.name })}>
                      <MoreHorizontal />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuSub>
                      <DropdownMenuSubTrigger>
                        <FolderInput />
                        {t('groups.moveTo')}
                      </DropdownMenuSubTrigger>
                      <DropdownMenuSubContent className="max-h-80 overflow-y-auto">
                        {targets(g).map((target) => (
                          <DropdownMenuItem
                            key={target.id}
                            onSelect={() => run({ op: 'moveGroup', id: g.id, parentId: target.id }, t('groups.moved', { name: g.name, group: target.name }))}
                          >
                            <span style={{ paddingInlineStart: `${target.depth * 0.75}rem` }}>{target.name}</span>
                          </DropdownMenuItem>
                        ))}
                      </DropdownMenuSubContent>
                    </DropdownMenuSub>
                    <DropdownMenuItem onSelect={() => setDeleting(g)}>
                      <Trash2 />
                      {t('bulk.deleteForGood')}
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </>
            ) : null}
          </li>
        ))}
      </ul>
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={t('groups.deleteTitle')}
        description={t('groups.deleteForGoodDescription', { name: deleting?.name ?? '' })}
        submit={t('bulk.deleteForGood')}
        errorFallback={t('entry.saveFailed')}
        onConfirm={() => {
          const group = deleting
          setDeleting(null)
          // In the bin, a delete is for good (the core's DeleteGroup).
          if (group) run({ op: 'deleteGroup', id: group.id }, t('groups.deletedForGood', { name: group.name }))
        }}
      />
    </section>
  )
}

import type { GroupView, VaultView } from '../vault/types'

/** Whether `id` is `ancestor` or inside it. */
export function isWithin(view: Pick<VaultView, 'groups'>, id: string, ancestor: string): boolean {
  const parents = new Map(view.groups.map((g) => [g.id, g.parentId]))
  const seen = new Set<string>()
  let current: string | null | undefined = id
  while (current && !seen.has(current)) {
    if (current === ancestor) return true
    seen.add(current)
    current = parents.get(current)
  }
  return false
}

/**
 * Where a group can move to, in the tree's order: any group outside the
 * recycle bin except itself, what is inside it and the group it is in now
 * (the core refuses the first two; the last changes nothing). The top group
 * and the bin themselves never move.
 */
export function groupTargets(view: Pick<VaultView, 'groups' | 'rootGroupId' | 'recycleBinId'>, group: GroupView): GroupView[] {
  if (group.id === view.rootGroupId || group.id === view.recycleBinId) return []
  return view.groups.filter((g) => !g.inRecycleBin && g.id !== group.parentId && !isWithin(view, g.id, group.id))
}

/** Whether a dragged group may drop onto `target` (a group outside the bin, or the bin while it is on). */
export function canDropGroup(view: Pick<VaultView, 'groups' | 'rootGroupId' | 'recycleBinId'>, groupId: string, target: string): boolean {
  const group = view.groups.find((g) => g.id === groupId)
  if (!group || group.id === view.rootGroupId || group.id === view.recycleBinId || group.inRecycleBin) return false
  if (target === view.recycleBinId) return true
  return groupTargets(view, group).some((g) => g.id === target)
}

/** The groups the recycle bin view lists: those directly in the bin (what they hold comes back with them). */
export function deletedGroups(view: Pick<VaultView, 'groups' | 'recycleBinId'>): GroupView[] {
  const bin = view.recycleBinId
  if (!bin) return []
  return view.groups
    .filter((g) => g.parentId === bin)
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true }))
}

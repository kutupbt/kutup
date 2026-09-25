import type { TFunction } from 'i18next'
import type { ChatGroupUpdate, ChatGroupUpdateChange } from '@kutup/chat-core/types'

/**
 * The sentences of a group change notice, one per change, as Signal words
 * them ("Alice changed the group name to “Hikers”.", "You added Bob.").
 * `name` turns a canonical address into a display name; `self` is this
 * account's address, for the "you" forms (separate keys: other languages
 * conjugate differently for "you").
 */
export function groupUpdateSentences(
  update: ChatGroupUpdate,
  self: string,
  name: (address: string) => string,
  t: TFunction,
): string[] {
  const byYou = update.actor === self
  const actor = name(update.actor)
  return update.changes.map((change) => sentence(change))

  function sentence(change: ChatGroupUpdateChange): string {
    const you = byYou ? '_you' : ''
    switch (change.type) {
      case 'nameChanged':
        return t(`chat.groupUpdates.nameChanged${you}`, { actor, name: change.name })
      case 'descriptionChanged':
        return change.description
          ? t(`chat.groupUpdates.descriptionChanged${you}`, { actor })
          : t(`chat.groupUpdates.descriptionRemoved${you}`, { actor })
      case 'pictureChanged':
        return change.removed
          ? t(`chat.groupUpdates.pictureRemoved${you}`, { actor })
          : t(`chat.groupUpdates.pictureChanged${you}`, { actor })
      case 'memberLeft':
        return change.member === self
          ? t('chat.groupUpdates.left_you')
          : t('chat.groupUpdates.left', { member: name(change.member) })
      case 'memberAdded':
      case 'memberRemoved':
      case 'adminGranted':
      case 'adminRevoked': {
        const key = { memberAdded: 'added', memberRemoved: 'removed', adminGranted: 'adminGranted', adminRevoked: 'adminRevoked' }[change.type]
        if (change.member === self) return t(`chat.groupUpdates.${key}_member_you`, { actor })
        return t(`chat.groupUpdates.${key}${you}`, { actor, member: name(change.member) })
      }
      case 'ownerAdded':
      case 'ownerRemoved':
        return change.member === self
          ? t(`chat.groupUpdates.${change.type}_member_you`)
          : t(`chat.groupUpdates.${change.type}`, { member: name(change.member) })
      case 'sendersChanged':
      case 'editorsChanged':
        return t(`chat.groupUpdates.${change.type}${you}`, {
          actor,
          who: change.administratorsOnly ? t('chat.groupUpdates.administrators') : t('chat.groupUpdates.allMembers'),
        })
      case 'inviteLinkEnabled':
        return t(`chat.groupUpdates.inviteLinkEnabled_${change.approvalRequired ? 'approval' : 'open'}${you}`, { actor })
      case 'inviteLinkApprovalChanged':
        return t(`chat.groupUpdates.inviteLinkApproval_${change.approvalRequired ? 'on' : 'off'}${you}`, { actor })
      case 'inviteLinkDisabled':
      case 'inviteLinkReset':
        return t(`chat.groupUpdates.${change.type}${you}`, { actor })
      case 'closed':
        return t(`chat.groupUpdates.closed${you}`, { actor })
    }
  }
}

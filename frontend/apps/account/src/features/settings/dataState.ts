import type { useTranslation } from 'react-i18next'
import type { LocalHeadEvent } from '@kutup/crypto/accountHead'

type TFunction = ReturnType<typeof useTranslation>['t']

/** One line of this app's own history with the account head, in words. */
export function describeHeadEvent(event: LocalHeadEvent, t: TFunction): { text: string; atMs: number } {
  switch (event.kind) {
    case 'startedFresh':
      return { text: t('accountHead.startedFresh', { sequence: event.anchor.sequence }), atMs: event.atMs }
    case 'forgotten':
      return { text: t('accountHead.forgotten', { from: event.from.sequence }), atMs: event.atMs }
    case 'reanchored': {
      const { from, to, status, atMs } = event.record
      const key =
        status.kind === 'tooOld' ? 'accountHead.reanchoredTooOld' : status.kind === 'fork' ? 'accountHead.reanchoredFork' : 'accountHead.reanchoredRollback'
      return { text: t(key, { from: from.sequence, to: to.sequence }), atMs }
    }
  }
}

// Copying secrets: cleared from the clipboard after a while, if still there.

import { toast } from 'sonner'
import { copyText } from '@kutup/ui/lib/clipboard'

/** A copied secret is cleared from the clipboard after this, if it is still there. */
const CLEAR_CLIPBOARD_MS = 30_000

export async function copySecret(value: string, done: string, cleared: string, notCleared: string) {
  await copyText(value)
  toast.success(done)
  setTimeout(() => {
    // Only what this copied is cleared: reading the clipboard needs the
    // browser's permission, and without it the person is told to clear it.
    void navigator.clipboard
      .readText()
      .then((now) => {
        if (now === value) return navigator.clipboard.writeText('').then(() => toast(cleared))
      })
      .catch(() => toast.warning(notCleared))
  }, CLEAR_CLIPBOARD_MS)
}


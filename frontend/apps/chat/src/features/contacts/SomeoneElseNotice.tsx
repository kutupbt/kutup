import { ShieldAlert } from 'lucide-react'

/**
 * An address that leads to someone else than the person the user knew
 * there (`resolveTyped`'s warning): said where the address was typed,
 * before anything opens (docs/plans/account-ids.md).
 */
export function SomeoneElseNotice({ text }: { text: string }) {
  return (
    <p
      role="alert"
      className="flex items-start gap-2 rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-sm"
      data-testid="chat-someone-else"
    >
      <ShieldAlert className="mt-0.5 size-4 shrink-0 text-status-warn" aria-hidden />
      <span>{text}</span>
    </p>
  )
}

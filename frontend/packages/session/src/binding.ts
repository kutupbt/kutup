import api from './client'
import { getSession, updateSession } from './store'

// What the account's sealed keys are bound to can change while a page is open:
// the account app re-seals them right after a sign-in
// (docs/plans/account-identity.md). A page that still seals for the old
// binding is refused with 409 `bindingChanged`; it refreshes here, seals
// again and retries once.

/** The account's current envelope binding, read again from the server and kept in the session. */
export async function refreshEnvelopeBinding(): Promise<string> {
  const { data } = await api.get<{ id: string; envelopeBinding: string }>('/user/me')
  const session = getSession()
  if (session && session.userId === data.id && session.envelopeBinding !== data.envelopeBinding) {
    updateSession({ envelopeBinding: data.envelopeBinding })
  }
  return data.envelopeBinding
}

/** Whether a request was refused for sealing with an old binding. */
export function isBindingChanged(error: unknown): boolean {
  const response = (error as { response?: { status?: number; data?: { code?: string } } } | null)?.response
  return response?.status === 409 && response.data?.code === 'bindingChanged'
}

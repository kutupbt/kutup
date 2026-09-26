import { useQuery } from '@tanstack/react-query'
import { deriveAccountIdentityKeys, toBase64 } from '@kutup/crypto'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'

export interface DriveIdentity {
  userId: string
  /** `username@server`, as named shares bind it. */
  account: string
  incarnationId: string
  masterKey: Uint8Array
  privateKey: Uint8Array
  /** This account's authority, which signs its folders' key histories. */
  authorityPublicKey: string
}

/**
 * What opening and sealing named shares needs besides the keys: this
 * account's canonical `username@server` and its incarnation id. Stable for a
 * session, so derived once.
 */
export function useDriveIdentity() {
  const session = useRequiredSession()
  return useQuery({
    queryKey: ['drive-identity', session.sessionId],
    staleTime: Infinity,
    queryFn: async (): Promise<DriveIdentity> => {
      const [{ data }, identity] = await Promise.all([
        api.get<{ chat?: { serverName?: string } }>('/auth/settings'),
        deriveAccountIdentityKeys(toBase64(session.masterKey)),
      ])
      const serverName = data.chat?.serverName
      if (!serverName) throw new Error('the server did not publish its name')
      if (!session.username) throw new Error('this account has no username')
      return {
        userId: session.userId,
        account: `${session.username}@${serverName}`,
        incarnationId: identity.incarnationId,
        masterKey: session.masterKey,
        privateKey: session.privateKey,
        authorityPublicKey: identity.authorityPublicKey,
      }
    },
  })
}

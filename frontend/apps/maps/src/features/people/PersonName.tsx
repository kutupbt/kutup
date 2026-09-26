import { personOf, usePeople } from '@kutup/drive-core/people'
import { Avatar } from '@kutup/ui/components/avatar'

/** Someone's picture and name (their address until they gave you their profile key). */
export function PersonName({
  account,
  size = 16,
  avatar = true,
  format,
}: {
  account: string
  size?: 16 | 24 | 32
  avatar?: boolean
  format?: (name: string) => string
}) {
  const people = usePeople()
  const { name, profile } = personOf(people.data, account)
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5 align-middle" title={account}>
      {avatar ? <Avatar name={name} image={profile?.avatar} contentType={profile?.avatarContentType} size={size} /> : null}
      <span className="truncate">{format ? format(name) : name}</span>
    </span>
  )
}

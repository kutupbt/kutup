import { Avatar } from '@kutup/ui/components/avatar'
import { personOf, usePeople } from '@kutup/drive-core/people'

/** Someone's picture and name (their address until they gave you their profile key). */
export function PersonLabel({ account, size = 16, format }: { account: string; size?: 16 | 24 | 32; format?: (name: string) => string }) {
  const people = usePeople()
  const { name, profile } = personOf(people.data, account)
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5 align-middle" title={account}>
      <Avatar name={name} image={profile?.avatar} contentType={profile?.avatarContentType} size={size} />
      <span className="truncate">{format ? format(name) : name}</span>
    </span>
  )
}

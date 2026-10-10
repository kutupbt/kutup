import type { Mailbox } from '@kutup/mail-core/mime'

/** A plausible address: one @, something either side, no spaces or brackets. */
export function isAddress(value: string): boolean {
  return /^[^\s@<>(),;:"[\]\\]+@[^\s@<>(),;:"[\]\\]+\.[^\s@<>(),;:"[\]\\]+$/.test(value)
}

/** Splits pasted text such as `A <a@x.org>, b@y.org` into mailboxes. */
export function parseRecipients(text: string): Mailbox[] {
  return text
    .split(/[,;\n]+/)
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const angled = /^(.*?)<([^>]+)>$/.exec(part)
      if (angled) return { name: angled[1].trim().replace(/^"|"$/g, ''), address: angled[2].trim().toLowerCase() }
      return { name: '', address: part.toLowerCase() }
    })
}

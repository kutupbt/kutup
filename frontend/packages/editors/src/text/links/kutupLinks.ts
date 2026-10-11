// Links from a note to Kutup items: `kutup:file/<id>` and `kutup:folder/<id>`.
// By id, so renames and moves keep them; inside the encrypted note, so the
// server learns nothing. A reader sees the item's current name and kind only
// when they can see the item themselves: a link grants no access.

export type KutupTarget = { type: 'file' | 'folder'; id: string }

const TARGET = /^kutup:(file|folder)\/([0-9a-fA-F-]{36})$/

export function parseKutupHref(href: string | undefined | null): KutupTarget | null {
  const m = TARGET.exec(href ?? '')
  return m ? { type: m[1] as 'file' | 'folder', id: m[2].toLowerCase() } : null
}

export function kutupHref(target: KutupTarget): string {
  return `kutup:${target.type}/${target.id}`
}

/** Whether the note links to any Kutup item (the lookup loads only then). */
export function hasKutupLinks(text: string): boolean {
  return /\(kutup:(?:file|folder)\/[0-9a-fA-F-]{36}\)/.test(text)
}

/** A link's Markdown, the name escaped for link text. */
export function kutupLinkMarkdown(name: string, target: KutupTarget, image = false): string {
  const text = name.replace(/([\\[\]])/g, '\\$1')
  return `${image ? '!' : ''}[${text}](${kutupHref(target)})`
}

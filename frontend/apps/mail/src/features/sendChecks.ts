/**
 * Proton's checks before a send (`useSendVerifications.tsx`): a no-reply
 * recipient, a missing subject, and an attachment the text mentions but the
 * message lacks. Each asks "Send anyway?" in the composer.
 */

/** Proton's `isNoReplyEmail`: the local part, dots, underscores and hyphens gone, holds "noreply" or "donotreply". */
export function isNoReplyAddress(address: string): boolean {
  const local = address.trim().toLowerCase().split('@')[0] ?? ''
  const folded = local.split('+')[0].replace(/[._-]/g, '')
  return folded.includes('noreply') || folded.includes('donotreply')
}

// Proton's English phrases (`emailAttachment.ts` EN_REGEX).
const EN =
  /see attached|see attachment|see included|is attached|attached is|are attached|attached are|attached to this email|attached to this message|I'm attaching|I am attaching|I've attached|I have attached|I attach|I attached|find attached|find the attached|find included|find the included|attached file|see the attached|see attachments|attached files|see the attachment|here is the attachment|attached you will find/i
// Kutup's Turkish ones (Proton has no Turkish), as whole words: "ekte" is
// never a part of "dikkate".
const TR =
  /(?<![\p{L}\p{N}])(ekte|ekteki|ekli dosya|ekli dosyalar|ek olarak gönder|ek olarak sun|ekledim|ekliyorum|eklenmiştir|iliştirdim|iliştiriyorum|ekte bulabilirsiniz|ekte gönderiyorum|ekte sunuyorum|dosyayı ekledim|dosyaları ekledim)(?![\p{L}\p{N}])/iu

/** The phrase that mentions an attachment, if the text has one (English or Turkish, whatever the app's language). */
export function mentionedAttachment(text: string): string | null {
  const flat = text.replace(/\s+/g, ' ')
  // Turkish in Turkish lower case: "EKLEDİM" is "ekledim", which /i alone misses.
  return flat.match(EN)?.[0] ?? flat.toLocaleLowerCase('tr-TR').match(TR)?.[0] ?? null
}

/**
 * What the sender wrote: the body without the quoted message and without the
 * signature (Proton's `locateBlockquote` and `removeSignatureFromHTMLMessage`),
 * so a mention in the mail answered, or in a signature, never asks.
 */
export function ownWords(body: { html: string } | { plain: string }, signature?: string): string {
  if ('plain' in body) {
    return body.plain
      .split('\n')
      .filter((line) => !line.trimStart().startsWith('>'))
      .join('\n')
  }
  const html = signature ? body.html.split(signature).join('') : body.html
  const doc = new DOMParser().parseFromString(html, 'text/html')
  doc.querySelectorAll('blockquote').forEach((quote) => quote.remove())
  return doc.body.textContent ?? ''
}

// One-time codes in mail (docs/plans/mail-parity.md, P3), as Proton's
// ItemOneTimeCode and ExtraOneTimeCode: a sign-in or verification code is
// found on the device and offered with Copy. Kutup's own detector, built on
// the same ideas: only recent mail with a code-like subject, candidates
// weighted by where they stand, one clear winner or nothing, and numbers
// that are the message's own date left out.

/** A code is acted on within minutes; older mail is not looked at (Proton's 20 minutes). */
export const ONE_TIME_CODE_MAX_AGE_MS = 20 * 60 * 1000

// Subjects that announce a code: English, Turkish, and the common German,
// French and Spanish forms. Promotions ("code for 20% off") are kept out.
const SUBJECT = new RegExp(
  [
    '(?:verification|log[\\s-]?in|sign[\\s-]?in|confirmation|activation|security|authentication|access|recovery|single[\\s-]?use)\\s+(?:pass)?code',
    'one[\\s-]?time[\\s-]?(?:pass(?:word|code)|code)',
    '\\botp\\b',
    '\\bpasscode\\b',
    '\\b\\d\\s*-?\\s*digit\\s+code',
    '\\b(?:2fa|mfa|auth)\\s+code',
    '\\byour\\s+code\\s+is\\b',
    "here['’]s\\s+your\\s+code",
    '\\b(?:two|2)[\\s-]?(?:factor|step)\\b',
    // Turkish
    '(?:doğrulama|giriş|güvenlik|onay|tek\\s+kullanımlık|aktivasyon|etkinleştirme|kimlik\\s+doğrulama)\\s+(?:kodu|kodunuz|şifresi|şifreniz)',
    '\\bkodunuz\\b',
    'tek\\s+kullanımlık\\s+şifre',
    // German, French, Spanish
    '(?:bestätigungs|sicherheits|anmelde|verifizierungs)code',
    'code\\s+de\\s+(?:v[ée]rification|connexion|s[ée]curit[ée]|confirmation)',
    'c[óo]digo\\s+de\\s+(?:verificaci[óo]n|seguridad|acceso|confirmaci[óo]n)',
  ].join('|'),
  'i',
)
const PROMO = /\b(?:off|discount|sale|coupon|promo(?:tion)?|voucher|gift)\b|indirim|kupon|%/i

/** Whether a subject announces a one-time code. */
export function isOneTimeCodeSubject(subject: string): boolean {
  const s = subject.normalize('NFKC')
  return SUBJECT.test(s) && !PROMO.test(s)
}

/** Recent enough to hold a live code. */
export function isRecent(at: number, now = Date.now()): boolean {
  return at > 0 && now - at >= -60_000 && now - at < ONE_TIME_CODE_MAX_AGE_MS
}

// A code: 4 to 8 digits, or 6 to 8 capitals and digits with at least one
// digit, alone; or digits split once by a space or hyphen (123 456).
const TOKEN = /(?<![\w-])(\d{4,8}|(?=[A-Z0-9]*\d)[A-Z0-9]{6,8}|\d{3,4}[ -]\d{3,4})(?![\w-])/g
// "code: 123456", "kodunuz 123456", "code is 123456".
const PHRASE = /(?:code|kod|kodu|kodunuz|şifre|şifreniz|passcode|otp|pin)\b[^\n\w]{0,3}(?:is|ist|est|es|:)?[\s:]*$/i

/** The send date's own numbers (20261012, 121026, …): never a code. */
function dateNumbers(at: number): Set<string> {
  const d = new Date(at)
  const yyyy = String(d.getFullYear())
  const yy = yyyy.slice(2)
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  return new Set([`${yyyy}${mm}${dd}`, `${dd}${mm}${yyyy}`, `${mm}${dd}${yyyy}`, `${yy}${mm}${dd}`, `${dd}${mm}${yy}`, `${mm}${dd}${yy}`, yyyy, `${dd}${mm}`, `${mm}${dd}`])
}

const normal = (code: string) => code.replace(/[ -]/g, '')

function candidates(text: string, weight: (before: string, line: string, code: string) => number, add: (code: string, score: number) => void) {
  for (const line of text.split(/\n/)) {
    for (const match of line.matchAll(TOKEN)) {
      const before = line.slice(0, match.index)
      add(normal(match[1]), weight(before, line, match[1]))
    }
  }
}

/**
 * The one-time code of a message, or null: the subject alone (the list,
 * which has no body) or with the body's text. Runs only on a code-like
 * subject of recent mail; the strict winner of the weighted candidates.
 */
export function oneTimeCode({ subject, text = '', at, now = Date.now() }: { subject: string; text?: string; at: number; now?: number }): string | null {
  if (!isRecent(at, now) || !isOneTimeCodeSubject(subject)) return null
  const scores = new Map<string, number>()
  const blocked = dateNumbers(at)
  const add = (code: string, score: number) => {
    if (score <= 0 || blocked.has(code) || /^(19|20)\d\d$/.test(code)) return
    scores.set(code, (scores.get(code) ?? 0) + score)
  }
  candidates(subject, (before, line, code) => (PHRASE.test(before) ? 4 : line.trim().endsWith(code) ? 3 : 2), add)
  candidates(
    text,
    // After "code:", alone on its line, or anywhere else (a little).
    (before, line, code) => (PHRASE.test(before) ? 5 : line.trim() === code ? 5 : /\d{3,4}[ -]\d{3,4}/.test(code) ? 0 : 1),
    add,
  )
  let best: string | null = null
  let top = 0
  let tie = false
  for (const [code, score] of scores) {
    if (score > top) {
      best = code
      top = score
      tie = false
    } else if (score === top) tie = true
  }
  return tie ? null : best
}

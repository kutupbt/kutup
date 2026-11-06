// Mail filters as Sieve (docs/plans/mail-filters.md, F4): the subset that
// maps to Kutup's filters, written and read as Proton writes it
// (`packages/sieve`: `address :all :comparator "i;unicode-casemap"` for
// sender and recipient, `header` for the subject, `exists "X-Attached"` for
// attachments, `fileinto` and `addflag`), so filters move between Kutup,
// Proton, Fastmail and Sieve servers. Sieve is not stored: the server runs
// Kutup's own filters. All of it runs in the browser, where folder and
// label names are open.

import type { FilterActions, FilterCondition, FilterField, FilterOp, MailFilter } from './filters'

/** Folders and labels by id, with names (a folder's name is its path: "Work/Clients"). */
export interface SievePlaces {
  folders: { id: string; path: string }[]
  labels: { id: string; name: string }[]
}

const SYSTEM = ['inbox', 'archive', 'spam', 'trash'] as const

/** Proton's spam guard: filters never run on spam (`SIEVE_SPAM_GUARD`). */
const SPAM_GUARD = `# Generated: Do not run this script on spam messages
if allof (environment :matches "vnd.proton.spam-threshold" "*",
spamtest :value "ge" :comparator "i;ascii-numeric" "\${1}")
{
    return;
}`

const quote = (text: string) => `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
/** A literal in a `:matches` key: `*` and `?` escaped (Proton's `escapeCharacters`). */
const literal = (text: string) => text.replace(/\\/g, '\\\\').replace(/([*?])/g, '\\$1')
/** A folder or label name in `fileinto`: a slash in a name is `\/`, a slash between folders is `/`. */
const pathName = (name: string) => name.replace(/\//g, '\\/')

function test(condition: FilterCondition): string {
  if (condition.field === 'attachments') return `${condition.negate ? 'not ' : ''}exists "X-Attached"`
  const [match, key] =
    condition.op === 'begins'
      ? [':matches', `${literal(condition.value)}*`]
      : condition.op === 'ends'
        ? [':matches', `*${literal(condition.value)}`]
        : [`:${condition.op}`, condition.value]
  const body =
    condition.field === 'subject'
      ? `header :comparator "i;unicode-casemap" ${match} "Subject" ${quote(key)}`
      : `address :all :comparator "i;unicode-casemap" ${match} ${condition.field === 'sender' ? '"From"' : '["To", "Cc", "Bcc"]'} ${quote(key)}`
  return condition.negate ? `not ${body}` : body
}

/** The filters, in order, as one Sieve script; a place gone since is left out of its filter. */
export function filtersToSieve(filters: MailFilter[], places: SievePlaces): string {
  const blocks = filters.map((filter) => {
    const into: string[] = []
    const folder = filter.actions.folder
    if (folder && (SYSTEM as readonly string[]).includes(folder)) into.push(folder)
    else if (folder?.startsWith('custom:')) {
      const found = places.folders.find((f) => f.id === folder.slice('custom:'.length))
      if (found) into.push(found.path.split('/').map(pathName).join('/'))
    }
    for (const id of filter.actions.labels ?? []) {
      const label = places.labels.find((l) => l.id === id)
      if (label) into.push(pathName(label.name))
    }
    const lines = [
      ...into.map((name) => `    fileinto ${quote(name)};`),
      ...(filter.actions.markRead ? ['    addflag "\\\\Seen";'] : []),
      ...(filter.actions.star ? ['    addflag "\\\\Flagged";'] : []),
    ]
    const tests = filter.conditions.map(test)
    const head = `# ${filter.name.replace(/[\r\n]+/g, ' ')}${filter.enabled ? '' : ' (off)'}`
    // A filter switched off stays in the script as a comment.
    const block = `if ${filter.match === 'all' ? 'allof' : 'anyof'} (${tests.join(',\n    ')})\n{\n${lines.join('\n')}\n}`
    return filter.enabled ? `${head}\n${block}` : `${head}\n${block.replace(/^/gm, '# ')}`
  })
  return [
    'require ["include", "environment", "variables", "relational", "comparator-i;ascii-numeric", "spamtest", "fileinto", "imap4flags"];',
    '',
    SPAM_GUARD,
    '',
    ...blocks.flatMap((block) => [block, '']),
  ].join('\n')
}

/** A filter read from Sieve, ready to save (its places resolved to ids). */
export interface ImportedFilter {
  name: string
  match: 'all' | 'any'
  conditions: FilterCondition[]
  actions: FilterActions
}

/** Why part of a script was not taken: `what` is the Sieve text in question. */
export interface SieveProblem {
  kind: 'syntax' | 'unsupported' | 'unknownPlace' | 'noAction'
  what: string
}

export interface SieveImport {
  filters: ImportedFilter[]
  problems: SieveProblem[]
}

// ---------------------------------------------------------------------------
// Reading: a tokenizer and a parser for the Sieve grammar (RFC 5228), then
// the subset Kutup's filters can hold.

type Token =
  | { kind: 'word'; value: string }
  | { kind: 'tag'; value: string }
  | { kind: 'string'; value: string }
  | { kind: 'number'; value: string }
  | { kind: 'comment'; value: string }
  | { kind: 'punct'; value: string }

function tokenize(source: string): Token[] {
  const tokens: Token[] = []
  let i = 0
  while (i < source.length) {
    const c = source[i]
    if (/\s/.test(c)) {
      i++
    } else if (c === '#') {
      const end = source.indexOf('\n', i)
      tokens.push({ kind: 'comment', value: source.slice(i + 1, end < 0 ? undefined : end).trim() })
      i = end < 0 ? source.length : end
    } else if (source.startsWith('/*', i)) {
      const end = source.indexOf('*/', i + 2)
      if (end < 0) throw new SyntaxError('an unclosed comment')
      tokens.push({ kind: 'comment', value: source.slice(i + 2, end).trim() })
      i = end + 2
    } else if (c === '"') {
      let value = ''
      i++
      for (;;) {
        if (i >= source.length) throw new SyntaxError('an unclosed string')
        const ch = source[i]
        if (ch === '\\' && i + 1 < source.length) {
          value += source[i + 1]
          i += 2
        } else if (ch === '"') {
          i++
          break
        } else {
          value += ch
          i++
        }
      }
      tokens.push({ kind: 'string', value })
    } else if (source.startsWith('text:', i)) {
      // Multi-line strings (`text: … .`): only in actions Kutup has none of.
      const end = source.indexOf('\n.\n', i)
      if (end < 0) throw new SyntaxError('an unclosed text: string')
      tokens.push({ kind: 'string', value: source.slice(source.indexOf('\n', i) + 1, end) })
      i = end + 3
    } else if (c === ':') {
      const m = /^:[A-Za-z_][\w-]*/.exec(source.slice(i))
      if (!m) throw new SyntaxError(`an unexpected ":" at ${i}`)
      tokens.push({ kind: 'tag', value: m[0].slice(1).toLowerCase() })
      i += m[0].length
    } else if (/[0-9]/.test(c)) {
      const m = /^[0-9]+[KMG]?/i.exec(source.slice(i))!
      tokens.push({ kind: 'number', value: m[0] })
      i += m[0].length
    } else if (/[A-Za-z_]/.test(c)) {
      const m = /^[A-Za-z_][\w.-]*/.exec(source.slice(i))!
      tokens.push({ kind: 'word', value: m[0].toLowerCase() })
      i += m[0].length
    } else if ('[](){},;'.includes(c)) {
      tokens.push({ kind: 'punct', value: c })
      i++
    } else {
      throw new SyntaxError(`an unexpected "${c}"`)
    }
  }
  return tokens
}

type Argument = { kind: 'tag'; value: string } | { kind: 'strings'; value: string[] } | { kind: 'number'; value: string }
interface Test {
  name: string
  args: Argument[]
  tests: Test[]
}
interface Command {
  name: string
  args: Argument[]
  test?: Test
  block?: Command[]
  /** The comment just before it (a filter's name, as Kutup and Proton write it). */
  comment?: string
}

class Parser {
  private at = 0
  private lastComment: string | undefined
  constructor(private readonly tokens: Token[]) {}

  private peek(): Token | undefined {
    while (this.tokens[this.at]?.kind === 'comment') {
      this.lastComment = this.tokens[this.at].value
      this.at++
    }
    return this.tokens[this.at]
  }
  private next(): Token {
    const token = this.peek()
    if (!token) throw new SyntaxError('the script ends too soon')
    this.at++
    return token
  }
  private expect(value: string) {
    const token = this.next()
    if (token.kind !== 'punct' || token.value !== value) throw new SyntaxError(`expected "${value}"`)
  }
  private isPunct(value: string) {
    const token = this.peek()
    return token?.kind === 'punct' && token.value === value
  }

  commands(inBlock: boolean): Command[] {
    const out: Command[] = []
    for (;;) {
      const token = this.peek()
      if (!token) {
        if (inBlock) throw new SyntaxError('a block is not closed')
        return out
      }
      if (inBlock && token.kind === 'punct' && token.value === '}') return out
      out.push(this.command())
    }
  }

  private command(): Command {
    this.peek()
    const comment = this.lastComment
    this.lastComment = undefined
    const name = this.next()
    if (name.kind !== 'word') throw new SyntaxError('expected a command')
    const args = this.arguments()
    let test: Test | undefined
    if (name.value === 'if' || name.value === 'elsif') test = this.test()
    if (this.isPunct('{')) {
      this.next()
      const block = this.commands(true)
      this.expect('}')
      return { name: name.value, args, test, block, comment }
    }
    this.expect(';')
    return { name: name.value, args, test, comment }
  }

  private arguments(): Argument[] {
    const args: Argument[] = []
    for (;;) {
      const token = this.peek()
      if (!token) return args
      if (token.kind === 'tag') args.push({ kind: 'tag', value: (this.next(), token.value) })
      else if (token.kind === 'number') args.push({ kind: 'number', value: (this.next(), token.value) })
      else if (token.kind === 'string') args.push({ kind: 'strings', value: [(this.next(), token.value)] })
      else if (token.kind === 'punct' && token.value === '[') {
        this.next()
        const list: string[] = []
        for (;;) {
          const item = this.next()
          if (item.kind !== 'string') throw new SyntaxError('expected a string in a list')
          list.push(item.value)
          if (this.isPunct(',')) this.next()
          else break
        }
        this.expect(']')
        args.push({ kind: 'strings', value: list })
      } else return args
    }
  }

  private test(): Test {
    const name = this.next()
    if (name.kind !== 'word') throw new SyntaxError('expected a test')
    const args = this.arguments()
    const tests: Test[] = []
    if (this.isPunct('(')) {
      this.next()
      for (;;) {
        tests.push(this.test())
        if (this.isPunct(',')) this.next()
        else break
      }
      this.expect(')')
    } else if (name.value === 'not') {
      tests.push(this.test())
    }
    return { name: name.value, args, tests }
  }
}

const strings = (args: Argument[]) => args.filter((a): a is { kind: 'strings'; value: string[] } => a.kind === 'strings')
const tags = (args: Argument[]) => args.filter((a): a is { kind: 'tag'; value: string } => a.kind === 'tag').map((a) => a.value)

/** Sieve's text of a test, for a problem's `what`. */
function show(test: Test): string {
  const args = test.args.map((a) => (a.kind === 'tag' ? `:${a.value}` : a.kind === 'number' ? a.value : a.value.length === 1 ? quote(a.value[0]) : `[${a.value.map(quote).join(', ')}]`))
  const inner = test.tests.length ? (test.name === 'not' ? ` ${show(test.tests[0])}` : ` (${test.tests.map(show).join(', ')})`) : ''
  return [test.name, ...args].join(' ') + inner
}

/** Proton's spam guard (or any `environment`/`spamtest` test whose block only returns): not a filter. */
function isGuard(command: Command): boolean {
  const names = new Set<string>()
  const walk = (t: Test) => {
    names.add(t.name)
    t.tests.forEach(walk)
  }
  if (command.test) walk(command.test)
  return (names.has('spamtest') || names.has('environment')) && (command.block ?? []).every((c) => c.name === 'return' || c.name === 'stop')
}

/** One test as Kutup conditions: several keys become several conditions (only where `anyof` keeps their meaning). */
function conditionsOf(test: Test, negate: boolean, any: boolean): FilterCondition[] | SieveProblem {
  if (test.name === 'not') return conditionsOf(test.tests[0], !negate, any)
  if (test.name === 'exists') {
    const [headers] = strings(test.args)
    if (headers?.value.length === 1 && headers.value[0].toLowerCase() === 'x-attached') return [{ field: 'attachments', op: 'contains', negate, value: '' }]
    return { kind: 'unsupported', what: show(test) }
  }
  if (test.name !== 'address' && test.name !== 'header') return { kind: 'unsupported', what: show(test) }
  const flags = tags(test.args)
  // Only the whole address, as Kutup's sender and recipient match it.
  if (flags.includes('localpart') || flags.includes('domain') || flags.includes('user') || flags.includes('detail')) return { kind: 'unsupported', what: show(test) }
  const comparatorAt = test.args.findIndex((a) => a.kind === 'tag' && a.value === 'comparator')
  const comparator = comparatorAt >= 0 ? (test.args[comparatorAt + 1] as { value: string[] } | undefined)?.value[0] : undefined
  if (comparator && comparator !== 'i;unicode-casemap' && comparator !== 'i;ascii-casemap') return { kind: 'unsupported', what: show(test) }
  const rest = strings(test.args).filter((_, i) => !(comparatorAt >= 0 && i === 0))
  if (rest.length !== 2) return { kind: 'syntax', what: show(test) }
  const [headers, keys] = [rest[0].value.map((h) => h.toLowerCase()), rest[1].value]
  let field: FilterField
  if (headers.length === 1 && headers[0] === 'subject') field = 'subject'
  else if (headers.length === 1 && headers[0] === 'from') field = 'sender'
  else if (headers.length > 0 && headers.every((h) => h === 'to' || h === 'cc' || h === 'bcc')) field = 'recipient'
  else return { kind: 'unsupported', what: show(test) }
  const kind = flags.find((f) => f === 'is' || f === 'contains' || f === 'matches' || f === 'regex' || f === 'value' || f === 'count') ?? 'is'
  if (kind !== 'is' && kind !== 'contains' && kind !== 'matches') return { kind: 'unsupported', what: show(test) }
  // Several keys are "any of them": one condition each, which needs anyof (or one key).
  if (keys.length !== 1 && !(any && !negate)) return { kind: 'unsupported', what: show(test) }
  return keys.map((key) => {
    let op: FilterOp = kind
    let value = key
    if (kind === 'matches') {
      const unescaped = (s: string) => s.replace(/\\([*?\\])/g, '$1')
      const wild = (s: string) => /(^|[^\\])[*?]/.test(s)
      // Proton writes begins with as "x*" and ends with as "*x".
      if (key.endsWith('*') && !key.endsWith('\\*') && !wild(key.slice(0, -1))) [op, value] = ['begins', unescaped(key.slice(0, -1))]
      else if (key.startsWith('*') && !wild(key.slice(1))) [op, value] = ['ends', unescaped(key.slice(1))]
    }
    return { field, op, negate, value }
  })
}

/** A `fileinto` name as Kutup's place: a system folder, a folder by its path, or a label. */
function placeOf(name: string, places: SievePlaces): { folder: string } | { label: string } | null {
  const lower = name.toLowerCase()
  if ((SYSTEM as readonly string[]).includes(lower)) return { folder: lower }
  // "A/B" is folder B in A; "A\/B" is one name with a slash.
  const path = name.split(/(?<!\\)\//).map((part) => part.replace(/\\\//g, '/'))
  const folder = places.folders.find((f) => f.path.split('/').length === path.length && f.path.toLowerCase() === path.join('/').toLowerCase())
  if (folder) return { folder: `custom:${folder.id}` }
  const label = places.labels.find((l) => l.name.toLowerCase() === path.join('/').toLowerCase())
  return label ? { label: label.id } : null
}

/** Reads a Sieve script: the filters Kutup can hold, and what it could not take. */
export function sieveToFilters(script: string, places: SievePlaces): SieveImport {
  let commands: Command[]
  try {
    commands = new Parser(tokenize(script)).commands(false)
  } catch (error) {
    return { filters: [], problems: [{ kind: 'syntax', what: error instanceof Error ? error.message : String(error) }] }
  }
  const filters: ImportedFilter[] = []
  const problems: SieveProblem[] = []
  let unnamed = 0
  for (const command of commands) {
    if (command.name === 'require' || command.name === 'stop' || command.name === 'keep') continue
    if (command.name === 'if' && isGuard(command)) continue
    if (command.name !== 'if' || !command.test) {
      problems.push({ kind: 'unsupported', what: command.name })
      continue
    }
    const top = command.test
    const any = top.name === 'anyof'
    const bare = top.name !== 'allof' && top.name !== 'anyof'
    const parts = bare ? [top] : top.tests
    const conditions: FilterCondition[] = []
    let failed: SieveProblem | null = null
    for (const part of parts) {
      const found = conditionsOf(part, false, any || bare)
      if (Array.isArray(found)) conditions.push(...found)
      else failed ??= found
    }
    const actions: FilterActions = {}
    for (const action of command.block ?? []) {
      const [values] = strings(action.args)
      if (action.name === 'fileinto' && values?.value.length === 1) {
        const place = placeOf(values.value[0], places)
        if (!place) failed ??= { kind: 'unknownPlace', what: values.value[0] }
        else if ('folder' in place) {
          // The first folder moves it; Sieve's later ones would copy, which Kutup does not.
          if (actions.folder) failed ??= { kind: 'unsupported', what: `fileinto ${quote(values.value[0])}` }
          else actions.folder = place.folder
        } else actions.labels = [...(actions.labels ?? []), place.label]
      } else if ((action.name === 'addflag' || action.name === 'setflag') && values) {
        for (const flag of values.value.flatMap((v) => v.split(/\s+/))) {
          if (flag.toLowerCase() === '\\seen') actions.markRead = true
          else if (flag.toLowerCase() === '\\flagged') actions.star = true
          else failed ??= { kind: 'unsupported', what: `${action.name} ${quote(flag)}` }
        }
      } else if (action.name === 'keep' || action.name === 'stop') {
        // Kutup keeps every message and runs every filter: nothing to do.
      } else failed ??= { kind: 'unsupported', what: action.name }
    }
    if (!failed && conditions.length === 0) failed = { kind: 'unsupported', what: show(top) }
    if (!failed && !actions.folder && !actions.labels?.length && !actions.markRead && !actions.star) failed = { kind: 'noAction', what: show(top) }
    if (failed) {
      problems.push(failed)
      continue
    }
    const name = command.comment?.split('\n')[0]?.replace(/^[*\s]+/, '').trim()
    // One test with several keys is "any of them" too.
    const match = any || (bare && conditions.length > 1) ? 'any' : 'all'
    filters.push({ name: name && !name.startsWith('@') ? name : `Sieve ${++unnamed}`, match, conditions, actions })
  }
  return { filters, problems }
}

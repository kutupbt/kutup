import { describe, expect, it } from 'vitest'
import type { MailFilter } from './filters'
import { filterToSieve, filtersToSieve, SIEVE_FILTER_REQUIRE, sieveToFilters, type SievePlaces } from './sieve'

const places: SievePlaces = {
  folders: [
    { id: 'f1', path: 'Work' },
    { id: 'f2', path: 'Work/Clients' },
  ],
  labels: [{ id: 'l1', name: 'Bills' }],
}

const filter = (over: Partial<MailFilter>): MailFilter => ({
  id: 'x',
  name: 'A filter',
  nameRevision: 1,
  enabled: true,
  position: 0,
  match: 'all',
  conditions: [],
  actions: {},
  source: 'manual',
  ...over,
})

describe('filters as Sieve (Proton’s dialect)', () => {
  it('writes the spam guard, the tests and the actions as Proton does', () => {
    const script = filtersToSieve(
      [
        filter({
          name: 'Clients',
          match: 'any',
          conditions: [
            { field: 'sender', op: 'ends', negate: false, value: '@client.test' },
            { field: 'subject', op: 'contains', negate: true, value: 'newsletter' },
            { field: 'attachments', op: 'contains', negate: false, value: '' },
          ],
          actions: { folder: 'custom:f2', labels: ['l1'], markRead: true, star: true },
        }),
      ],
      places,
    )
    expect(script).toContain('if allof (environment :matches "vnd.proton.spam-threshold" "*",')
    expect(script).toContain('# Clients\nif anyof (address :all :comparator "i;unicode-casemap" :matches "From" "*@client.test",')
    expect(script).toContain('not header :comparator "i;unicode-casemap" :contains "Subject" "newsletter"')
    expect(script).toContain('exists "X-Attached"')
    expect(script).toContain('fileinto "Work/Clients";\n    fileinto "Bills";\n    addflag "\\\\Seen";\n    addflag "\\\\Flagged";')
  })

  it('reads back what it writes: a round trip keeps every filter', () => {
    const filters = [
      filter({
        name: 'Clients',
        match: 'any',
        conditions: [
          { field: 'sender', op: 'ends', negate: false, value: '@client.test' },
          { field: 'recipient', op: 'begins', negate: false, value: 'sales*' },
          { field: 'subject', op: 'matches', negate: true, value: 'Re: ?eport*' },
          { field: 'attachments', op: 'contains', negate: true, value: '' },
        ],
        actions: { folder: 'custom:f2', labels: ['l1'], markRead: true },
      }),
      filter({ name: 'Trash spam words', conditions: [{ field: 'subject', op: 'is', negate: false, value: 'Win "big"' }], actions: { folder: 'trash', star: true } }),
    ]
    const read = sieveToFilters(filtersToSieve(filters, places), places)
    expect(read.problems).toEqual([])
    expect(read.filters).toEqual(filters.map(({ name, match, conditions, actions }) => ({ name, match, conditions, actions })))
  })

  it('leaves a switched-off filter out, as a comment', () => {
    const script = filtersToSieve([filter({ enabled: false, conditions: [{ field: 'subject', op: 'is', negate: false, value: 'x' }], actions: { star: true } })], places)
    expect(script).toContain('# A filter (off)\n# if allof')
    expect(sieveToFilters(script, places).filters).toEqual([])
  })

  it('reads a Proton script: its comment header, several keys, setflag', () => {
    const proton = `require ["include", "environment", "variables", "relational", "comparator-i;ascii-numeric", "spamtest"];
require ["fileinto", "imap4flags"];
# Generated: Do not run this script on spam messages
if allof (environment :matches "vnd.proton.spam-threshold" "*", spamtest :value "ge" :comparator "i;ascii-numeric" "\${1}") {
    return;
}
/**
 * @type or
 * @comparator contains
 */
if anyof (address :all :comparator "i;unicode-casemap" :contains "From" ["alice@x.test", "bob@x.test"]) {
    fileinto "archive";
    setflag "\\\\Seen";
    keep;
}`
    const read = sieveToFilters(proton, places)
    expect(read.problems).toEqual([])
    expect(read.filters).toEqual([
      {
        name: 'Sieve 1',
        match: 'any',
        conditions: [
          { field: 'sender', op: 'contains', negate: false, value: 'alice@x.test' },
          { field: 'sender', op: 'contains', negate: false, value: 'bob@x.test' },
        ],
        actions: { folder: 'archive', markRead: true },
      },
    ])
  })

  it('names what it cannot take, and takes the rest', () => {
    const script = `require ["fileinto", "regex", "vacation"];
# Unknown place
if header :contains "Subject" "x" { fileinto "Nowhere"; }
# Regex
if header :regex "Subject" "^a" { fileinto "archive"; }
# Domain part
if address :domain :is "From" "x.test" { fileinto "archive"; }
# Vacation
if true { vacation "away"; }
# All of several keys
if allof (header :contains "Subject" ["a", "b"]) { fileinto "archive"; }
# Fine
if header :is "subject" "ok" { fileinto "Work"; }`
    const read = sieveToFilters(script, places)
    expect(read.filters).toEqual([{ name: 'Fine', match: 'all', conditions: [{ field: 'subject', op: 'is', negate: false, value: 'ok' }], actions: { folder: 'custom:f1' } }])
    expect(read.problems.map((p) => p.kind)).toEqual(['unknownPlace', 'unsupported', 'unsupported', 'unsupported', 'unsupported'])
    expect(read.problems[0].what).toBe('Nowhere')
  })

  it('says where a script is broken', () => {
    const broken = 'if header :is "Subject" "x" { fileinto "archive";'
    expect(sieveToFilters(broken, places).problems).toEqual([{ kind: 'syntax', what: 'a block is not closed', from: broken.length - 1, to: broken.length }])
    // An unclosed string or comment points at where it starts.
    const string = 'if header :is "Subject" "x { keep; }'
    expect(sieveToFilters(string, places).problems[0]).toMatchObject({ kind: 'syntax', from: string.indexOf('"x') })
    const comment = 'keep;\n/* never closed'
    expect(sieveToFilters(comment, places).problems[0]).toMatchObject({ kind: 'syntax', from: comment.indexOf('/*') })
    // A token that doesn't fit: marked where it stands.
    const token = 'if header :is "Subject" "x" ) { keep; }'
    const problem = sieveToFilters(token, places).problems[0]
    expect(token.slice(problem.from, problem.to)).toBe(')')
  })

  it('marks each problem on the text it names', () => {
    const script = `require ["fileinto", "vacation"];
if header :contains "Subject" "x" { fileinto "Nowhere"; }
if header :regex "Subject" "^a" { fileinto "archive"; }
vacation "away";
if header :is "Subject" "y" { keep; }`
    const read = sieveToFilters(script, places)
    const marked = read.problems.map((p) => [p.kind, script.slice(p.from, p.to)])
    expect(marked).toEqual([
      ['unknownPlace', 'fileinto "Nowhere";'],
      ['unsupported', 'header :regex "Subject" "^a"'],
      ['unsupported', 'vacation "away";'],
      ['noAction', 'if header :is "Subject" "y" { keep; }'],
    ])
  })
})

describe('one filter as the Sieve editor shows it', () => {
  const fields = ['sender', 'recipient', 'subject'] as const
  const ops = ['contains', 'is', 'begins', 'ends', 'matches'] as const

  it('round-trips every field, operator, negation and action', () => {
    for (const field of fields) {
      for (const op of ops) {
        for (const negate of [false, true]) {
          for (const match of ['all', 'any'] as const) {
            const one = filter({
              match,
              conditions: [
                { field, op, negate, value: op === 'matches' ? 'a*b?c' : 'Wörk "x" \\ y' },
                { field: 'attachments', op: 'contains', negate, value: '' },
              ],
              actions: { folder: 'custom:f2', labels: ['l1'], markRead: true, star: true },
            })
            const read = sieveToFilters(filterToSieve(one, places), places)
            expect(read.problems, `${field} ${op} ${negate} ${match}`).toEqual([])
            expect(read.filters.map(({ match, conditions, actions }) => ({ match, conditions, actions }))).toEqual([{ match, conditions: one.conditions, actions: one.actions }])
          }
        }
      }
    }
    for (const folder of ['inbox', 'archive', 'spam', 'trash', 'custom:f1']) {
      const one = filter({ conditions: [{ field: 'subject', op: 'is', negate: false, value: 'x' }], actions: { folder } })
      expect(sieveToFilters(filterToSieve(one, places), places).filters[0].actions).toEqual({ folder })
    }
  })

  it('has no spam guard or name, and shows a switched-off filter as it would run', () => {
    const script = filterToSieve(filter({ enabled: false, conditions: [{ field: 'subject', op: 'is', negate: false, value: 'x' }], actions: { star: true } }), places)
    expect(script.startsWith(SIEVE_FILTER_REQUIRE)).toBe(true)
    expect(script).not.toContain('spamtest')
    expect(script).not.toContain('# A filter')
    expect(sieveToFilters(script, places).filters).toHaveLength(1)
  })
})

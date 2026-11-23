# Mail: the Sieve editor (mail-parity F4)

Status: approved 2026-11-18 (Q-1: the text is not kept; Q-2: per filter; Q-3: server Sieve out, roadmap line added). Built on feat/mail-sieve-editor; spec 200 waits for the browser runs.

## What Proton does

`packages/components/containers/filters/modal/advanced/`:

- **AdvancedFilterModal**: one filter per modal, with a name and its Sieve
  script. A new one starts from `sieveTemplates[2]`: the `require` line and
  the generated spam guard.
- **SieveEditor**: CodeMirror 5, `mode: 'sieve'`, line numbers, a lint gutter.
  It is lazy loaded (`SieveForm`'s `lazy()`) and dark-themed with the app.
- **Checking**: on save the script goes to the server
  (`checkSieveFilter`, version 2). The issues it returns become lint
  annotations, and saving is refused while there are any.
- **Closing with changes** asks before discarding them (`CloseFilterModal`).
- **The filter list** (`FilterItemRow`): a simple filter offers "Edit" and
  "Edit Sieve"; a filter its simple form can't hold (`isSieve`) offers only
  "Edit Sieve". The toolbar has "Add filter" and "Add sieve filter".
- The server stores the Sieve text and runs it.

## Where Kutup differs, and why

Kutup's server runs filters as condition JSON (docs/plans/mail-filters.md,
F2), not as Sieve. The batch's `sieve.ts` already reads a script into those
filters (`sieveToFilters`, with the problems it can't take) and writes them
back (`filtersToSieve`). So the editor is **a Sieve view of Kutup filters**,
checked in the browser:

- What the editor accepts is exactly what `sieveToFilters` can hold: tests on
  sender, recipient, subject and attachments (`:is`, `:contains`,
  `:matches`, begins and ends, `not`, `allof` / `anyof`); `fileinto`,
  `addflag "\\Seen"` / `"\\Flagged"` and the labels.
- Anything else is a lint error, and the filter can't be saved. Examples:
  `vacation`, `reject`, `redirect`, `body`, `header` on other fields,
  `variables`, `if`/`elsif` chains, and several filters in one script. The
  message names it, and says so is "not something Kutup filters can do".
- No server round trip: client-only, as requested. The check is the same
  code the import uses.

Running real Sieve on the server is the alternative. Stalwart has an
engine, but Kutup's filters act on Kutup folders and labels, after the
mail is encrypted. That would be a separate design; this plan doesn't take
it (Q-3).

## Design

### 1. Entry points (as Proton's)

In `FiltersSettingsPage.tsx`:

- **The toolbar** gains "Add Sieve filter", beside "Add filter",
  "Import Sieve" and "Export Sieve".
- **Each filter's row** gains "Edit as Sieve" beside "Edit". Every Kutup
  filter has both forms, so unlike Proton nothing is Sieve-only (`isSieve`
  is always false).

### 2. The dialog: `SieveFilterDialog.tsx` (mail app)

- **Name**: the same field and checks as `FilterDialog`: required, and
  unique among the filters. The name is sealed as now.
- **Script**:
  - for a new filter, a template: a `require ["fileinto", "imap4flags"];`
    line and a commented example `if` block. Kutup's spam rule is the
    server's, so there's no spam guard;
  - for an existing filter, `filtersToSieve([filter], places)`, cut to that
    filter's block plus the `require` line.
- **Live check**, debounced at 300 ms:
  - `sieveToFilters(text, places)` runs;
  - the result must be **exactly one filter and no problems**;
  - "No filter in this script" and "Only one filter per Sieve filter" are
    errors too: Proton's advanced filter is one script, and an `if` per
    filter keeps the mapping one to one.
- **Save**:
  - refused while there are errors;
  - otherwise saves the one filter's match, conditions and actions through
    the existing `useCreateFilter` / `useUpdateFilter`. Its `enabled` and
    `position` are kept on an edit and are the defaults for a new one;
  - the filter is then a normal filter: "Edit" opens it in the form editor.
- **Formatting and comments aren't kept**: what is saved is the filter, and
  the next "Edit as Sieve" shows the script as `filtersToSieve` writes it.
  The dialog says so in one line under the editor (en and tr). See Q-1.
- **Closing with changes** asks first, as Proton's `CloseFilterModal`
  ("Discard your changes?").
- **A place that's gone** (a folder or label deleted since) is the existing
  `unknownPlace` problem, shown at its `fileinto` line.

### 3. The editor component: `SieveEditor.tsx` (lazy)

- CodeMirror 6, already in the lockfile (`@kutup/editors` depends on it;
  `@codemirror/lint` 6.9.7 comes in through `codemirror`). The mail app
  declares its own direct dependencies at the same versions, so the lockfile
  gains no new package:
  - `@codemirror/view`, `state`, `language`, `lint`, `commands`;
  - Sieve highlighting from `@codemirror/legacy-modes/mode/sieve` through
    `StreamLanguage` (the mode Proton's CodeMirror 5 used);
  - line numbers, the lint gutter, the app's light and dark theme through
    CSS variables (no `theme-one-dark` import), and `aria-label` on the
    content.
- **Lazy loaded** with `React.lazy`, as Proton's `SieveForm`, so the mail
  app's entry chunk doesn't grow. `scripts/check-app-bundles.mjs` keeps
  holding.
- **Lint**: `linter()` maps each problem to a `Diagnostic` at its range,
  severity error. `lintGutter()` shows them. The list under the editor
  repeats them in words, for screen readers and phones.
- **Phones**: the dialog goes full screen below `sm`; CodeMirror keeps its
  native text input.

### 4. `sieve.ts`: positions

- Problems today carry only `what` (the text). The tokenizer gains
  `from`/`to` offsets per token, and `SieveProblem` gains
  `from?: number; to?: number`.
- Syntax errors become a `syntax` problem with the offset where they arose,
  instead of a thrown `SyntaxError` the caller turns into a single problem.
  The import dialog keeps working, since it reads only `kind` and `what`.
- Tests in `sieve.test.ts`:
  - each problem kind has a range covering its text;
  - an unclosed string or comment points at its start;
  - the round trip `sieveToFilters(filtersToSieve([f]))` gives `f` back for
    every condition operator and action (already partly covered; made
    exhaustive).

### 5. Strings

New keys in the mail app's `en.json` and `tr.json`, under `sieve.editor.*`:

- the title (add and edit);
- the name field;
- the one-filter and no-filter errors;
- the "comments and formatting aren't kept" note;
- the discard confirmation;
- the "not something Kutup filters can do" message per unsupported construct;
- `aria-label`s.

No hard-coded English.

### 6. Tests

- **Vitest**:
  - `sieve.test.ts` as above;
  - `SieveFilterDialog.test.tsx`, which checks that:
    - the template shows for a new filter;
    - an existing filter opens as its script;
    - an error blocks save;
    - two `if` blocks block save;
    - save calls create or update with the parsed filter;
    - close with changes asks.
- **Browser spec** (`tests/e2e/specs/200-mail-sieve-editor.spec.ts`, added
  to the ci.yml mail browser job):
  - add a Sieve filter that files mail from one sender into a folder with
    a label;
  - send such a mail and see it filed;
  - open the filter as Sieve and see the same rule;
  - type `vacation` and see save refused with the message.

## Slices

One PR after the wipe:

1. `sieve.ts` positions and tests.
2. The editor component and the dialog, with the strings.
3. The page's entry points and the browser spec.

## Questions

- **Q-1. Keep the user's text?** Proton keeps the script as written,
  comments included, because Sieve is what it stores. Kutup stores the
  filter, so the text is regenerated. Keeping it would need a column on
  `mail_filters` (sealed like the name, limited by a site setting). It would
  also need a rule for when a form edit makes the stored text stale (drop
  it). I'd leave it out: no schema change in W7's window, and the form and
  the script stay one truth. Your call.
- **Q-2. Whole-account script or per filter?** "The account's Sieve script"
  could mean one editor for all filters at once. Proton edits one filter per
  script, and the import/export already covers the whole set as one script,
  so I'd follow Proton (per filter).
- **Q-3. Server-side Sieve** (vacation, redirect, etc. through Stalwart's
  engine) stays out. Kutup already has those actions as features of their
  own, both built (mail-parity: Forwarding with conditions, Auto-reply), so
  the editor's refusal names them: "use Settings → Forwarding" for
  `redirect`, and "Settings → Auto-reply" for `vacation`.

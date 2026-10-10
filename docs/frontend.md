# Web frontend design and architecture

Kutup's web client is a React 18, strict-TypeScript, Vite application. Its
current interface follows the **Polar Workspace** design system: quiet,
information-dense work surfaces, a restrained blue/cyan polar palette, and one
small three-facet brand motif. The interface is original to Kutup; shadcn/Radix
primitives provide accessible behavior rather than a copied page template.

## Product structure

Authenticated desktop and tablet layouts use one persistent application shell:

- **Files** and **Messages** are the primary workspaces.
- **Shared with me** and **Trash** are subordinate Files views.
- **Settings** remains in the workspace shell.
- Authorized **Admin** routes replace the workspace shell with a dedicated
  full-height Admin sidebar and top bar. They share theme and account controls,
  but never stack administrative navigation beside Files/Messages navigation.
- Editors and viewers use focused chrome so document space is not reduced by
  application navigation.

Phones use the same routes, service ownership, and data state with a
CSS-responsive presentation. The primary phone navigation contains exactly
Files, Messages, and Account. Native iOS and Android applications are separate
work in progress and are not described as shipped by this web architecture.

## Theme contract

Semantic tokens live in `frontend/src/index.css`. Components should use roles
such as `background`, `surface`, `foreground`, `muted-foreground`, `border`,
`primary`, `destructive`, and their sidebar equivalents. Do not choose a raw
color for an ordinary product state. Brand artwork, collaborator identity
colors, syntax rendering, and file-format artwork are the narrow exceptions.

Light, Dark, and System are explicit persisted preferences. Use
`ThemeSelector` where all choices fit and `useThemePreference` for a compact
menu. `System` remains selected while the resolved OS theme changes; it is not
silently converted into Light or Dark.

Typography is self-hosted and documented in `frontend/FONTS.md`:

- Manrope for display roles;
- Source Sans 3 for product text; and
- IBM Plex Mono for code and identifiers.

No runtime font, decorative image, or tracking request is permitted.

## Component boundaries

- `components/layout/AuthenticatedShell.tsx` owns the persistent frame.
- `components/layout/AppSidebar.tsx` owns desktop application navigation.
- `components/mobile/MobileBottomNav.tsx` owns phone application navigation.
- `components/admin/AdminSidebar.tsx` and `AdminTopBar.tsx` own the dedicated,
  role-gated Admin frame.
- `components/theme/ThemeSelector.tsx` owns explicit theme preference.
- `components/auth/` owns shared authentication composition.
- `components/drive/` owns Files presentation; `pages/Drive.tsx` retains data
  and operation ownership across responsive changes.
- `chat/ConversationRow.tsx` and `chat/MessageScroller.tsx` own reusable
  Messages presentation behavior; `pages/Chat.tsx` retains protocol/service
  ownership.
- `packages/editors` (`FileEditorPage`) is the focused editor/viewer frame,
  shared by Office (documents) and Drive (other files).

Viewport changes must not duplicate network services, clear drafts, reset a
folder, interrupt uploads, or issue mutations. Prefer CSS responsive classes.
Use `useIsMobile` only when a genuinely different interaction primitive or
single presentation branch is required, while keeping effects and business
state above the branch.

## Implementation rules

- Authored frontend sources are `.ts` and `.tsx`; do not add `.js` or `.jsx`.
- Use pnpm and the lockfile in `frontend/`.
- Prefer semantic HTML, landmarks, native buttons, visible focus, and Radix
  primitives for overlays and menus.
- Every icon-only action needs an accessible name. Status changes that matter
  without focus movement need an appropriate live region.
- Touch targets, safe-area insets, reduced motion, 200% text, and reflow are
  first-order requirements rather than a later mobile port.
- Visible operations must be backed by a real capability. Do not ship a dead
  toggle, placeholder destination, or button that leads to a different action.
- Preserve established E2E selectors when reshaping behavior-heavy surfaces,
  especially Messages and editors.

## Display and identity contracts

- Files and folders use one Drive surface. Modified timestamps are locale-aware
  and unambiguous through minutes; a day-and-month-only label is insufficient.
- Storage usage is a read-only, accessible progress meter with used and total
  values. It must not look clickable or imply an unavailable quota-purchase
  action; quota changes belong to authorized Admin settings.
- Messages presents an editable, account-private installation name as the
  human identity. The smaller numeric device ID is immutable protocol-routing
  metadata, not a suggested device name. Renaming changes neither keys,
  sessions, manifest membership, nor history.

## Local verification

Run cheap gates before starting the Compose/browser matrix:

```sh
pnpm --dir frontend test
pnpm --dir frontend run build:web
git diff --check
```

Then rebuild the local Compose stack and run the affected Playwright specs.
`tests/e2e/specs/35-polar-workspace-accessibility.spec.ts` covers key Light/Dark
and phone/desktop states with axe and verifies responsive transitions do not
reload Files data or replace the active Chat device. Playwright keeps retries
at zero. See `tests/e2e/README.md` for exact commands and sensitive-artifact
rules.

The implementation and delivery record is maintained in
`docs/plans/polar-workspace-frontend-redesign.md`.

## Manual acceptance checklist

Run this checklist against a production build after the automated browser
matrix is green. Use synthetic local accounts and content; do not capture a
recovery phrase, access token, private message, or stable account identifier in
screenshots or bug reports.

### Navigation and responsive state

- [ ] At 1440×900 and 1024×768, Files and Messages are peer workspaces;
  Shared with me and Trash appear only within Files; Settings keeps the
  workspace sidebar; authorized Admin routes use the dedicated Admin shell
  without a second stacked sidebar.
- [ ] At 390×844 and 430×932, primary navigation contains exactly Files,
  Messages, and Account. It respects the bottom safe area and never covers a
  row, sheet action, or message composer.
- [ ] At 768×1024, rotate between portrait and landscape while a folder is
  open and while a Messages thread has an unsent draft. The folder, selection,
  draft, and active conversation remain unchanged.
- [ ] Open every canonical route directly and reload it: `/drive`,
  `/drive/shared`, `/drive/trash`, `/chat`, `/settings`, `/admin`, a file deep
  link, and a public-share link. Authentication and authorization redirects
  remain correct.

### Theme, language, and visual quality

- [ ] Review Login, Register, First Login, Recovery, Files, Messages, Settings,
  Admin, one focused editor, and one public share in Light and Dark.
- [ ] Select System, change the operating-system appearance in both
  directions, and confirm the preference remains System across reload.
- [ ] Repeat phone navigation and the main authentication forms in Turkish.
  Labels do not truncate, overlap, or cause horizontal page scrolling.
- [ ] Confirm surfaces, borders, text hierarchy, focus rings, file-type colors,
  status colors, and the Kutup facet are legible and restrained in both themes.

### Keyboard and assistive access

- [ ] Complete Login, Files navigation, file actions, Messages navigation and
  sending, Settings theme selection, Admin tabs, and sign-out without a
  pointer. Focus order follows the visible layout and remains visible.
- [ ] Open and close menus, dialogs, inspectors, and sheets with the keyboard.
  Escape closes only the top layer and focus returns to the invoking control.
- [ ] With a screen reader, confirm one main landmark, labeled primary
  navigation, ordered headings, named forms/search regions, meaningful button
  names, and useful status announcements on representative pages.
- [ ] At 200% text size and 400% browser zoom, representative pages reflow
  without two-dimensional scrolling, excluding spreadsheets and whiteboards.
- [ ] Enable forced colors and reduced motion. Controls remain identifiable,
  focus remains visible, and nonessential transitions stop.

### Behavior and privacy

- [ ] Create, upload, open, rename, share, download, trash, restore, and
  permanently delete synthetic Files content; then open the same state after a
  responsive transition.
- [ ] Send Direct and group messages with a reply, edit, reaction, deletion,
  expiry, and attachment. Restored history and lazy media retain their existing
  security and availability states.
- [ ] Verify Settings, TOTP/devices, authorized Admin actions, version history,
  editor save/sync state, and public-share download behavior.
- [ ] Confirm Drive modified timestamps identify the date and time through
  minutes, storage renders as a read-only progress meter, and a Chat
  installation can be renamed without changing its numeric protocol device ID.
- [ ] Confirm resizing, opening navigation, changing theme, and restoring a
  page do not themselves send a message, receipt, backup operation, file
  mutation, or eager protected-media request.

# Mail: Proton Mail parity

**Status:** the goal, set 2026-10-11 ("a proper mail implementation, Proton
Mail feature parity in the end"). This is the gap list: every feature of
Proton Mail's web client, where Kutup stands, and the order to close the
gaps. Each slice gets its own plan before it is built; keep this list
current as they land.

Read from `WebClients` (2026-10-11): the app in `applications/mail`, its
settings in `applications/account/src/app/containers/mail/routes.tsx`
(General, Email privacy, Identity and addresses, Folders and labels,
Filters, Forward and auto-reply, Domain names, Encryption keys, IMAP/SMTP,
Backup and export), and `packages/components/containers`. Gmail is the
reference only where Proton has nothing.

**Key:** ✅ done (on master or live) · 🔶 in a pull request or planned ·
❌ missing · ➖ not for Kutup, or comes with another app.

## Reading

| Feature | Proton | Kutup |
|---|---|---|
| End-to-end mail between users, zero-access for the rest, padlocks | `EncryptionStatusIcon.tsx` | ✅ C2, C3 |
| OpenPGP with outside users: WKD, Autocrypt, trusting a sender's key | `TrustPublicKeyModal.tsx` | ✅ C3 |
| Threads in the reading pane | `MessageView.tsx` | ✅ |
| Conversation or message mode in the list | `ViewModeToggle.tsx` | ✅ conversation grouping on by default, as Proton's (Settings → General); a row stands for the thread's messages there: count, senders, unread and starred as a whole, actions on all; counters count conversations |
| Layout (column or row), resizable list, density | `ViewLayoutCards.tsx`, `DensityRadiosCards.tsx` | ✅ Settings → Appearance: column or row, comfortable or compact, composer normal or maximized; the list resizes (drag or arrow keys), remembered per browser |
| Quick filters (unread, has attachments), sort (date, size) | `FilterList.tsx` | ❌ |
| Paging, page size, select all across pages | `PagingControls.tsx`, `SelectAllBanner.tsx` | 🔶 "load more" only |
| Selection pane for several messages | `SelectionPane.tsx` | ❌ |
| Right-click menu, Shift/Ctrl selection, drag to folders, undo | `ItemContextMenu.tsx` | ✅ |
| Sender card, Save to contacts, Chat and Call | recipient dropdown | ✅ (Chat, Call are Kutup's) |
| Keyboard shortcuts and their overlay | `MailShortcutsModal.tsx` | ✅ list keys; ❌ message keys R, Shift+R, F |
| Dark mode body, folded quotes | `ExtraDarkStyle.tsx`, blockquote toggle | ✅ |
| Attachment thumbnails in the list, preview, download all | `ItemAttachmentThumbnails.tsx`, `AttachmentPreview.tsx` | ❌ (download one by one) |
| Print, view headers, view HTML, export .eml | `MessagePrintModal.tsx`, `MessageHeadersModal.tsx` | 🔶 .eml only |
| Remote images blocked until allowed | `ExtraImages.tsx` | ✅ |
| Image proxy, tracker protection (pixels, UTM links) | `transformRemote.ts`, `SpyTrackerModal.tsx` | ❌ |
| Link confirmation | `LinkConfirmationModal.tsx` | ❌ |
| Phishing report, spam score banner | `MessagePhishingModal.tsx`, `ExtraSpamScore.tsx` | ❌ |
| Unsubscribe banner (List-Unsubscribe), auto-unsubscribe | `ExtraUnsubscribe.tsx` | ❌ |
| Read receipts (ask, show) | `ExtraReadReceipt.tsx` | ❌ |
| Snooze, Snoozed folder | `SnoozeDropdown.tsx` | ❌ |
| One-time code detection with Copy | `ItemOneTimeCode.tsx` | ❌ |
| Sender images (BIMI, logos) | `SenderImagesToggle.tsx` | ❌ (initials and contact photos) |
| Expiring message banner | `ExtraExpiration.tsx` | ❌ (with expiring messages) |

## Writing

| Feature | Proton | Kutup |
|---|---|---|
| Rich text editor, attachments, drafts autosave | RoosterJS, `useAutoSave.tsx` | ✅ (Tiptap) |
| Plain text mode, default font and size, text direction | `DraftTypeSelect.tsx`, `FontFaceSelect.tsx`, `TextDirectionSelect.tsx` | ❌ |
| Docked, minimised, maximised composer | `ComposerModeCards.tsx` | ✅ (dimmed when maximised) |
| Insert and paste images, inline or attached, emoji | `ComposerInsertImageModal.tsx`, `EditorCustomPastePlugin.ts` | ❌ |
| Signatures per address, display name | `PMSignatureField.tsx`, `IdentitySection.tsx` | 🔶 your address: Mail → Settings → Identity (rich signature, display name); shared mailboxes later |
| From picker (addresses, shared mailboxes, aliases) | `SelectSender.tsx` | ✅ shared mailboxes; 🔶 aliases plan |
| Contact groups as recipients, drag between To/Cc/Bcc | `AddressesGroupItem.tsx`, `useAddressesInputDrag.ts` | ❌ (suggestions only) |
| Pre-send warnings (keys, recipients) | `SendWithWarningsModal.tsx` | 🔶 per-recipient locks, refusals |
| Encrypt and sign: per contact, "Sign external messages" | `ContactEmailSettingsModal.tsx`, `ExternalPGPSettingsSection.tsx` | ✅ Contacts → Email settings: Encrypt, Sign, PGP scheme per address; "Sign outside mail" in General |
| Contact keys: found online and trusted in one table, several per address, history | `ContactKeysTable.tsx`, `ContactPGPSettings.tsx` | ✅ [`contact-keys.md`](contact-keys.md): WKD/Proton/KOO keys, Trust, Untrust, Use for sending, Download, Remove; expired and revoked kept |
| Per-message Encrypt and Sign toggles in the composer | (none) | ✅ beyond Proton ([`mail-encrypt-sign.md`](mail-encrypt-sign.md)) |
| Scheduled send, Scheduled folder | `ScheduleSendActions.tsx` | ❌ |
| Undo send (delay) | `DelaySendSecondsSelect.tsx` | ❌ |
| Expiring messages | `ComposerExpirationModal.tsx` | ❌ |
| Password-protected mail to outside people, their reply page | `ComposerPasswordModal.tsx`, `eo/` | ❌ |
| Remove image metadata on upload | `RemoveImageMetadataToggle.tsx` | ❌ |
| Mailto handler, "default mail app" | `useMailtoHash.ts` | ❌ |
| Request a read receipt | `MoreActionsExtension.tsx` | ❌ |
| Writing assistant | `ComposerAssistant.tsx` | ➖ not planned |

## Organising

| Feature | Proton | Kutup |
|---|---|---|
| Inbox, Drafts, Sent, Starred, Archive, Spam, Trash, All mail | `MailSidebarSystemFolders.tsx` | ✅ |
| Delete for good, empty a folder | `MessagePermanentDeleteModal.tsx` | ✅ delete chosen, "Delete all" in Trash and Spam |
| Spam and Trash emptied after 30 days | `AutoDeleteSetting.tsx` | ✅ "Auto-delete unwanted messages" (off by default, as Proton), banner with Enable |
| Almost all mail, keep moved messages in Sent | `AlmostAllMailToggle.tsx` | ✅ All mail in the sidebar, "Exclude Spam/Trash from All mail"; ❌ keep moved messages in Sent |
| Custom folders (nested), labels | `FoldersSection.tsx` | ✅ F1, names sealed ([`mail-filters.md`](mail-filters.md)) |
| Filters, "Always move sender's emails", apply to existing | `FiltersSection.tsx` | ✅ F2 |
| Block, spam, allow lists | `SpamFiltersSection.tsx` | ✅ F3 (allow needs DMARC) |
| Sieve editor | `AdvancedFilterModal.tsx` | 🔶 F4 |
| Search on subject and addresses | | ✅ |
| Advanced search (from, to, dates, folder, attachments) | `AdvancedSearch.tsx` | ❌ |
| Body search in the browser (encrypted local index) | `contentSearch/` | ❌ (C2f; [`browser-storage`](../research/16-browser-storage-architecture.md)) |
| Category tabs (Primary, Promotions, …) | `categoriesTabs` | ❌ |
| Newsletter subscriptions view | `NewsletterSubscriptionView.tsx` | ❌ |

## Addresses and identity

| Feature | Proton | Kutup |
|---|---|---|
| Address keys: rotate, import, export, retire | `AddressKeysSection.tsx` | ✅ C3 |
| PGP settings: sign outside mail, attach key, PGP/MIME or inline | `ExternalPGPSettingsSection.tsx` | ✅ Settings → General: Sign outside mail, Attach public key, Default PGP scheme; Inline sends plain text with each file encrypted (`.pgp`) or signed (`.sig`); the reader opens and checks Inline with files; scheme per contact in Contacts → Email settings |
| Key transparency, address verification | `KTToggle.tsx` | ❌ |
| Post-quantum keys | `PostQuantumKeysOptInSection.tsx` | ❌ |
| Distribution lists, shared mailboxes | (business: groups) | ✅ |
| Aliases (hide-my-email) | Pass aliases | 🔶 aliases plan (`feat/mail-aliases`) |
| Dots, dashes, capitals and `+tags` ignored | `CANONICALIZE_SCHEME.PROTON` | 🔶 aliases A0 |
| Several addresses per account, default address | `AddressesSection.tsx` | ❌ |
| Custom domains (MX, SPF, DKIM, DMARC checks), catch-all | `DomainModal.tsx`, `CatchAllSection.tsx` | ❌ (Phase E, organisations) |
| Forwarding (with conditions, end to end to Kutup users) | `ForwardSection.tsx` | ❌ (with filters' actions) |
| Auto-reply (vacation responder, schedules) | `AutoReplySection.tsx` | ✅ fixed, daily, weekly, monthly, permanent in a time zone; once per sender every 7 days; never to lists or automatic mail; kept in Sent; Proton's banner on received auto-replies |
| Save contacts automatically | `AutomaticallySaveContacts.tsx` | ➖ Kutup asks first (contacts plan) |

## Notifications

| Feature | Proton | Kutup |
|---|---|---|
| Unread count in the title | `useMailboxFavicon.ts` | ✅ (favicon count missing) |
| Desktop notifications for new mail | `useNewEmailNotification.ts` | ❌ |
| Web push | | ❌ (C2f) |
| Daily email summary | `DailyEmailNotificationToggle` | ❌ |
| Per-folder notifications | label `Notify` | 🔶 F1 (the switch), with push |

## Data, clients, privacy

| Feature | Proton | Kutup |
|---|---|---|
| Import from Gmail, Outlook, IMAP (Easy Switch) | `activation/` | ❌ |
| Export, backup | `ImportExportAppSection.tsx` | ❌ (.eml per message) |
| IMAP and SMTP for desktop clients (Bridge), SMTP tokens | `ProtonMailBridgeSection.tsx`, `SMTPSubmissionSection.tsx` | ❌ (a local bridge, as Proton's, keeps E2EE) |
| Mobile apps | | ➖ native apps' plans |
| Offline cache | (none; local search index only) | ❌ ([`browser-storage`](../research/16-browser-storage-architecture.md)) |
| Calendar invitations in mail (Accept, Decline) | `ExtraEvent.tsx` | ➖ with Calendar |
| Privacy settings page (remote content, tracking, links, embedded images) | `EmailPrivacySection.tsx` | ❌ |
| Security logs | `LogsSection.tsx` | 🔶 account app has sessions |
| Language, date format | `LanguageAndTimeSection.tsx` | ✅ (account preferences) |
| Settings for mail (one place) | mail routes | ✅ Mail → Settings: General, Appearance, Identity, Auto-reply, Folders and labels, Filters, Block and allow; keys in Account |

## Order

Each is its own plan and pull request, Proton first:

1. **What is in flight:** aliases A0–A3.
2. **P1 organising:** folders, labels, filters, block lists
   ([`mail-filters.md`](mail-filters.md) F1–F3), with the Mail → Settings
   area they need, auto-empty Spam and Trash, Empty folder, Almost all mail.
   First because nearly everything after it files into these places or
   adds a setting to that area.
   Then **Encrypt and Sign per message** ([`mail-encrypt-sign.md`](mail-encrypt-sign.md)),
   as its own pull request.
3. **P2 Mail settings and identity:** a Mail → Settings area (layout,
   density, conversation mode, composer defaults, privacy switches),
   display name and signatures per address, auto-reply, PGP settings.
4. **P3 reading:** quick filters and sort, paging and select all,
   attachment previews and thumbnails, print, headers and HTML, link
   confirmation, unsubscribe, phishing report, read receipts, message
   shortcuts (R, Shift+R, F).
5. **P4 writing:** undo send, scheduled send, snooze, inline images and
   emoji, plain text mode, contact groups as recipients, mailto handler.
6. **P5 privacy:** image proxy and tracker protection, expiring messages,
   password-protected mail to outside people.
7. **P6 search and notifications:** advanced search, body search in the
   browser, desktop notifications and web push.
8. **P7 moving in and out:** import (IMAP, Gmail, Outlook), export,
   forwarding, a bridge for desktop clients.
9. **P8 organisation:** several addresses, custom domains, catch-all,
   categories, newsletter view, key transparency (Phase E for domains).

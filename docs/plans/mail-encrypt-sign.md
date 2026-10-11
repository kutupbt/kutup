# Mail: Encrypt and Sign per message

**Status:** agreed 2026-10-11; slices 1–3 built on `feat/mail-encrypt-sign`, except the "Sign outside mail" setting, which joins Mail → Settings → General once that page (#101) is on master; until then Sign starts on. ([`mail-parity.md`](mail-parity.md))
Goes beyond Proton, which has no per-message switches.

## Goal

Two buttons in the composer footer, **🔒 Encrypt** and **✍️ Sign**, that
decide for the message being written whether it is encrypted end to end
and whether it is signed. "Unencrypted but signed" is one of the outcomes:
anyone can read it, and anyone with the sender's key can check it is
theirs and unchanged.

## How Proton does it

- Mail between Proton users is always end-to-end encrypted; there is no
  switch.
- For outside addresses, per contact: "Encrypt emails" and "Sign emails"
  (`ContactEmailSettingsModal.tsx`, `SignEmailsSelect.tsx`), PGP/MIME or
  inline; account-wide "Sign external messages"
  (`ExternalPGPSettingsSection.tsx`).
- No per-message control in the composer, except password protection for
  outside people.

## Decisions (2026-10-11)

1. **Encryption can be turned off per message, Kutup recipients too**
   (beyond Proton, which never allows it between its users).
2. **Two visible buttons in the composer footer** (as Thunderbird), not a
   menu; each recipient chip shows what will happen to it.
3. **Order:** right after P1, as its own pull request.

## How it works

- **Defaults:** Encrypt on whenever every recipient can receive encrypted
  mail (Kutup users, outside people with a known or pinned key); Sign on,
  from a new account setting "Sign outside mail" (on) and the per-contact
  Sign flag Contacts already keeps. Turning a button off is for this
  message only.
- **Encrypt off, Kutup recipients:** the message is sent readable to the
  server, which encrypts it to each recipient's key on arrival, like mail
  from outside (zero-access, the plain padlock instead of the end-to-end
  one). The composer says so before sending: "Kutup can read this message
  while delivering it." The sender's own copy in Sent stays encrypted to
  them.
- **Encrypt off, outside recipients:** sent as plain mail over TLS, as to
  anyone without a key.
- **Sign:** an OpenPGP signature with the sender's address key, PGP/MIME
  (`multipart/signed`), which Proton, Thunderbird and GnuPG check.
  Kutup's own readers check it against the sender's key list as now.
  Off sends without a signature.
- **Recipient chips:** each shows the result (end to end; readable to the
  server on delivery; plain; signed or not), as the locks do today.
- **The reading side:** a signed but unencrypted message shows "signed by
  …, not encrypted" in its padlock.

## Slices

1. Server: accept readable MIME for Kutup recipients when the sender asks
   (`mail_send.rs`), encrypt on arrival as `insert_message` does for
   outside mail; signed-only PGP/MIME from the composer.
2. App: the two buttons, the per-recipient chips, the warning, the
   "Sign outside mail" setting in Mail → Settings; the padlock for
   signed-but-unencrypted mail.
3. Tests: the mail gate (a signed-only message checked by GnuPG; an
   unencrypted message between Kutup users stored zero-access), a browser
   spec.

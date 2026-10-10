# Mail with Proton: the manual check

End-to-end mail between Kutup and Proton cannot run in the mail gate (it needs
a real Proton account and Kutup reachable from the internet), so it is checked
by hand on a deployed server before the MX switch and after any change to
PGP handling (docs/plans/mail.md, C3). The gate covers the same paths against
GnuPG (`scripts/test-mail-inbound.sh`).

You need a Kutup account on the deployed server (`you@kutup.dev`), a free
Proton account (`you@proton.me`), and the server's WKD answering (the
direct method, docs/self-hosting.md):

```sh
curl -sS -o /dev/null -w '%{http_code}\n' "https://kutup.dev/.well-known/openpgpkey/policy"
# 200
```

## 1. Kutup to Proton

1. In Kutup Mail, write to `you@proton.me`. The recipient chip shows a
   padlock; its tooltip says the key is Proton's ("End-to-end encrypted with
   the recipient's Proton key").
2. Send. The sent copy's padlock in Kutup says "End-to-end encrypted".
3. In Proton, the message opens with a padlock: "PGP-encrypted and signed
   message" (Proton verifies signatures only with keys you trust). The
   message shows a banner offering to trust the sender's key (from the
   Autocrypt header). Trust it.
4. Send another message from Kutup. Proton now shows "PGP-encrypted message
   from verified sender".

## 2. Proton to Kutup

1. In Proton, write to `you@kutup.dev`. Proton finds the key through Kutup's
   WKD and shows a padlock on the recipient ("End-to-end encrypted"). Send.
2. In Kutup Mail the message has a padlock: "PGP-encrypted and signed
   message", and a banner: "you@proton.me sent their public key" (Proton
   attaches it when "Attach public key" is on in its settings; otherwise no
   banner).
3. Trust the key. The padlock becomes "PGP-encrypted message from verified
   sender", and Contacts shows the key under `you@proton.me` as Trusted.
4. Reply from Kutup: the recipient chip's tooltip now says "End-to-end
   encrypted with a key you trust".

## 3. Things that must not happen

- Proton receives the Kutup message as plaintext (its padlock says "Stored
  with zero-access encryption").
- Kutup shows "Sender verification failed" for a Proton message after its key
  was trusted.
- A message to a Proton address and a Gmail address at once sends the Gmail
  copy encrypted, or the Proton copy in clear: the Proton copy is PGP/MIME,
  the Gmail copy plaintext, and the sent copy says "Sent with zero-access
  encryption".

Record the date, the Kutup version (image tag) and the results in the pull
request that changed PGP handling.

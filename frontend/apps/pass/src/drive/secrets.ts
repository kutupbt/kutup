// Vault secrets (docs/plans/pass.md, "Vault secrets"): what opens a vault,
// kept in the account sealed under the master key, so a vault opens with the
// Kutup sign-in, as Proton Pass does. The server stores them unreadable,
// bound to the account's key binding and the vault (docs/plans/account-identity.md).

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { revisionGuard } from "@kutup/crypto";
import { fromBase64 } from "@kutup/crypto/base64";
import { accountHead, HeadBlockedError } from "@kutup/session/accountHead";
import { ScopeRecords, type RecordsPage } from "@kutup/session/accountRecords";
import api from "@kutup/session/client";
import { getSession, type Session } from "@kutup/session/store";
import { masterKeysBytes } from "@kutup/crypto/masterKeys";
import {
  openKept,
  resealKeptKey,
  type KeptKey,
  type VaultHandle,
} from "../vault/client";
import type { VaultKeyInput } from "../vault/types";

// What is kept, and how, is decided once, in Rust (kutup_pass::kept, through
// the Pass worker); this file only moves records to and from the server.
// A kept key carries its revision (docs/plans/sealed-revisions.md): one older
// than this browser has seen is not used, and a new one is stored only on top
// of the one it replaces.

/**
 * What has become of a secret's vault: only an `open` one's key is used. The
 * others are listed as the account head lists them, and kept until their
 * owner forgets them (the key may be the only copy of a generated password
 * or a key file's element, for a downloaded copy of the vault).
 */
export type SecretState = "open" | "trashed" | "unreachable" | "gone";

export interface SecretRow {
  fileId: string;
  envelope: string;
  state: SecretState;
  /** The revision in the envelope's header, as the server read it. */
  revision: number;
  /**
   * The revision the account head vouches for (docs/plans/rollback-protection.md),
   * when it covers the vault secrets: the key must open at exactly this one.
   */
  vouched?: number;
}

/** What the revision guard calls a vault's kept key. */
const KEPT_SCOPE = "pass-vault-secret";

export const secretsKey = ["pass", "vault-secrets"] as const;

/**
 * The vault secrets are the account-records scope `passSecrets`
 * (docs/plans/account-records.md), one record per vault file, under the
 * account head.
 */
const SCOPE = "passSecrets";

function headFor(session: Session) {
  return accountHead(session);
}

/**
 * The scope's records, read without the head: only while this app is
 * blocked on another history (reads go on, held to this browser's own
 * guard, and the banner says why).
 */
async function unverifiedRecords(): Promise<ScopeRecords> {
  const copy = new ScopeRecords(SCOPE);
  for (let pages = 0; pages < 10_000; pages++) {
    const page = (
      await api.get<RecordsPage>(
        `/account/records/${SCOPE}?after=${copy.cursor}`,
      )
    ).data;
    if (copy.merge(page) === "done") return copy;
  }
  throw new Error("the vault secrets did not end");
}

/**
 * The account's vault secrets in use (those of vaults open to it), held to
 * the head: every page's head verified and the whole scope checked against
 * it (one more, one fewer or another revision is refused), and each row
 * carries the revision it must open at. Refused, no kept key is used:
 * vaults open with their password. What has become of each vault (in the
 * trash, out of reach) the server says apart, from its Drive rows.
 */
export async function loadVaultSecrets(session: Session): Promise<SecretRow[]> {
  let copy: ScopeRecords;
  let verified = true;
  try {
    copy = await (await headFor(session)).records(SCOPE);
  } catch (error) {
    if (!(error instanceof HeadBlockedError)) throw error;
    copy = await unverifiedRecords();
    verified = false;
  }
  const states = new Map(
    (
      await api.get<{ fileId: string; state: SecretState }[]>(
        "/pass/vault-states",
      )
    ).data.map((row) => [row.fileId, row.state]),
  );
  return [...copy.records]
    .map(([fileId, record]): SecretRow => ({
      fileId,
      envelope: record.envelope,
      state: states.get(fileId) ?? "gone",
      revision: record.revision,
      ...(verified ? { vouched: record.revision } : {}),
    }))
    .filter((row) => row.state === "open");
}

export function useVaultSecrets() {
  return useQuery({
    queryKey: secretsKey,
    queryFn: () => {
      const session = getSession();
      if (!session) throw new Error("not signed in");
      return loadVaultSecrets(session);
    },
  });
}

async function openRow(
  session: Session,
  rows: SecretRow[] | undefined,
  fileId: string,
): Promise<KeptKey | null> {
  const row = rows?.find((r) => r.fileId === fileId);
  if (!row) return null;
  try {
    const kept = await openKept(
      row.envelope,
      masterKeysBytes(session.masterKeys),
      session.envelopeBinding,
      fileId,
    );
    // Not the one the account head vouches for: rolled back, or brought back.
    if (row.vouched !== undefined && kept.revision !== row.vouched) return null;
    // Older than one this browser has seen: the server replaying an old key.
    await revisionGuard(session).accept(KEPT_SCOPE, fileId, kept.revision);
    return kept;
  } catch {
    // Sealed for another account or vault, or replayed: as if there were none.
    return null;
  }
}

/**
 * The kept key of vault `fileId`, if the account keeps one that opens: the
 * password as its SHA-256 (what is kept of a password the person chose).
 */
export async function keptKey(
  session: Session,
  rows: SecretRow[] | undefined,
  fileId: string,
): Promise<VaultKeyInput | null> {
  const secret = await openRow(session, rows, fileId);
  if (!secret) return null;
  return {
    password: null,
    passwordHash: secret.passwordHash ? fromBase64(secret.passwordHash) : null,
    keyFile: secret.keyFile ? fromBase64(secret.keyFile) : null,
  };
}

/**
 * What kind of key the account keeps for vault `fileId`: one Kutup Pass
 * generated (kept nowhere else unless saved), one the person chose, or
 * `unknown` when it does not open here (to be treated as generated).
 */
export async function keptKeyKind(
  session: Session,
  rows: SecretRow[] | undefined,
  fileId: string,
): Promise<"generated" | "chosen" | "unknown" | "none"> {
  if (!rows?.some((r) => r.fileId === fileId)) return "none";
  const secret = await openRow(session, rows, fileId);
  if (!secret) return "unknown";
  return secret.generatedPassword ? "generated" : "chosen";
}

/** The vault's key to show, when Kutup Pass generated it (for KeePass apps). */
export async function keptGeneratedPassword(
  session: Session,
  rows: SecretRow[] | undefined,
  fileId: string,
): Promise<string | null> {
  return (await openRow(session, rows, fileId))?.generatedPassword ?? null;
}

/** A kept key sealed for a vault, ready to store. */
export interface SealedKey {
  envelope: string;
  revision: number;
  /** The revision it replaces (0: none). */
  base: number;
}

/**
 * Stores a kept key for vault `fileId`, with the next account head. Stored
 * already (a retry after an answer that was lost) counts as stored: the
 * head's index then lists this very revision, and nothing is sent again.
 */
export async function putKeptKey(
  session: Session,
  fileId: string,
  sealed: SealedKey,
): Promise<void> {
  await (
    await headFor(session)
  ).recordsWrite(SCOPE, (copy) =>
    Promise.resolve(
      copy.records.get(fileId)?.revision === sealed.revision
        ? null
        : {
            puts: [
              {
                id: fileId,
                revision: sealed.revision,
                envelope: sealed.envelope,
              },
            ],
            deletes: [],
            done: undefined,
          },
    ),
  );
  // Stored: remembering it here is best effort (a store that fails only
  // means this browser trusts the next read, as a fresh one does).
  await revisionGuard(session)
    .accept(KEPT_SCOPE, fileId, sealed.revision)
    .catch(() => undefined);
}

/**
 * Keeps the key the account keeps for vault `from` for its copy `to` as well
 * (the copy has the same key), so the copy opens with the sign-in too. The
 * kept secret moves as it is, in the worker: no vault is opened and no
 * password is needed. False when nothing usable is kept for `from`.
 */
export async function keepCopiedKey(
  session: Session,
  rows: SecretRow[] | undefined,
  from: string,
  to: string,
): Promise<boolean> {
  // Only one the account head vouches for, and not a replay.
  if (!(await openRow(session, rows, from))) return false;
  const row = rows!.find((r) => r.fileId === from)!;
  const revision = await revisionGuard(session).next(KEPT_SCOPE, to, 0);
  const envelope = await resealKeptKey(
    row.envelope,
    masterKeysBytes(session.masterKeys),
    session.envelopeBinding,
    from,
    to,
    revision,
  );
  await putKeptKey(session, to, { envelope, revision, base: 0 });
  return true;
}

/** Seals the key of the vault open in `vault` to replace the kept one at `base`. */
export async function sealVaultKey(
  session: Session,
  fileId: string,
  vault: VaultHandle,
  base: number,
  generated = false,
): Promise<SealedKey> {
  const revision = await revisionGuard(session).next(KEPT_SCOPE, fileId, base);
  const envelope = await vault.keepKey(
    masterKeysBytes(session.masterKeys),
    session.envelopeBinding,
    fileId,
    revision,
    generated,
  );
  return { envelope, revision, base };
}

/**
 * Keeps the key of the vault open in `vault` (the key it was opened or made
 * with) for `fileId`, on top of the key kept now, with the next account head.
 * When another device kept one meanwhile: done if it is this same key;
 * otherwise again on top of it (this vault's key is the one just used). A
 * password the person chose is kept only as its SHA-256; a `generated` one
 * as it is, to be shown.
 */
export async function keepVaultKey(
  session: Session,
  fileId: string,
  vault: VaultHandle,
  generated = false,
): Promise<void> {
  const kept = await (
    await headFor(session)
  ).recordsWrite(SCOPE, async (copy, attempt) => {
    const now = copy.records.get(fileId);
    if (
      attempt > 1 &&
      now &&
      (await vault.keptKeyIsMine(
        now.envelope,
        masterKeysBytes(session.masterKeys),
        session.envelopeBinding,
        fileId,
      ))
    ) {
      // Another device kept this same key first: nothing to send.
      return { puts: [], deletes: [], done: now.revision };
    }
    const sealed = await sealVaultKey(
      session,
      fileId,
      vault,
      now?.revision ?? 0,
      generated,
    );
    return {
      puts: [
        { id: fileId, revision: sealed.revision, envelope: sealed.envelope },
      ],
      deletes: [],
      done: sealed.revision,
    };
  });
  if (kept !== undefined)
    await revisionGuard(session).accept(KEPT_SCOPE, fileId, kept);
}

export function useKeepVaultKey() {
  const queryClient = useQueryClient();
  return async (
    session: Session,
    fileId: string,
    vault: VaultHandle,
    generated = false,
  ): Promise<void> => {
    await keepVaultKey(session, fileId, vault, generated);
    await queryClient.invalidateQueries({ queryKey: secretsKey });
  };
}

/** Forgets the kept key of vault `fileId`, with the next account head (gone already: nothing to do). */
export async function forgetVaultKey(
  session: Session,
  fileId: string,
): Promise<void> {
  await (
    await headFor(session)
  ).recordsWrite(SCOPE, (copy) =>
    Promise.resolve(
      copy.records.has(fileId)
        ? { puts: [], deletes: [fileId], done: undefined }
        : null,
    ),
  );
}

export function useForgetVaultKey() {
  const queryClient = useQueryClient();
  return async (fileId: string): Promise<void> => {
    const session = getSession();
    if (!session) throw new Error("not signed in");
    await forgetVaultKey(session, fileId);
    await queryClient.invalidateQueries({ queryKey: secretsKey });
  };
}

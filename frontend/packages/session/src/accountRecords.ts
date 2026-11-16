/**
 * The account-records store (docs/plans/account-records.md, W3): a device's
 * copy of one scope and the batches made on it. The same rules as
 * `kutup_crypto::account_records`, whose registry this mirrors. Reading and
 * writing go through `AccountHead.records` and `AccountHead.recordsWrite`,
 * which verify every page's head and check the index once caught up.
 */

/** The scopes of the store (`RecordScope` in kutup-crypto). */
export type RecordScopeName =
  "passSecrets" | "pins" | "chatGroups" | "chatContacts";

/** One record as a device keeps it. */
export interface StoredRecord {
  revision: number;
  /** The sealed record, canonical base64. */
  envelope: string;
}

/** One page, as `GET /api/account/records/{scope}` answers. */
export interface RecordsPage {
  records: { id: string; revision: number; envelope: string; seq: number }[];
  deleted: { id: string; seq: number }[];
  next: number;
  more: boolean;
  resync: boolean;
  head: string | null;
  basis: string | null;
}

/** What a records batch changes, and what the write returns once stored. */
export interface RecordsEdit<T> {
  /** New or changed records, each at the revision its envelope was sealed at. */
  puts: readonly { id: string; revision: number; envelope: string }[];
  deletes: readonly string[];
  done: T;
}

/** A batch's items, each on the copy's revision. */
export interface RecordsBatch {
  scope: RecordScopeName;
  puts: {
    id: string;
    baseRevision: number;
    revision: number;
    envelope: string;
  }[];
  deletes: { id: string; baseRevision: number }[];
}

/** A device's copy of one scope: its records and how far it has read. */
export class ScopeRecords {
  /** The `next` of the last page merged; 0 before the first. */
  cursor = 0;
  readonly records = new Map<string, StoredRecord>();

  constructor(readonly scope: RecordScopeName) {}

  /**
   * Merges a page read from `cursor`: 'more' (read on), 'done' (check the
   * index against the page's head before using the copy) or 'resync' (the
   * copy was emptied; read from 0). Refuses changes out of counter order.
   */
  merge(page: RecordsPage): "more" | "done" | "resync" {
    if (page.resync) {
      this.records.clear();
      this.cursor = 0;
      return "resync";
    }
    const changes = [
      ...page.records.map((record) => ({
        seq: record.seq,
        id: record.id,
        record,
      })),
      ...page.deleted.map((gone) => ({
        seq: gone.seq,
        id: gone.id,
        record: null,
      })),
    ].sort((a, b) => a.seq - b.seq);
    let last = this.cursor;
    for (const change of changes) {
      if (!Number.isSafeInteger(change.seq) || change.seq <= last)
        throw new Error(`${this.scope}: records page out of order`);
      last = change.seq;
      if (change.record) {
        if (!(change.record.revision >= 1))
          throw new Error(`${this.scope}: a record at revision 0`);
        this.records.set(change.id, {
          revision: change.record.revision,
          envelope: change.record.envelope,
        });
      } else {
        this.records.delete(change.id);
      }
    }
    if (!Number.isSafeInteger(page.next) || page.next < last)
      throw new Error(`${this.scope}: the records cursor goes back`);
    this.cursor = page.next;
    return page.more ? "more" : "done";
  }

  /** `(id, revision)` sorted by id: what the head's index names. */
  index(): [string, number][] {
    return [...this.records]
      .map(([id, record]): [string, number] => [id, record.revision])
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  }

  /** A batch on this copy; each base revision is the copy's (0: new). */
  plan(edit: Pick<RecordsEdit<unknown>, "puts" | "deletes">): RecordsBatch {
    const named = new Set<string>();
    const once = (id: string) => {
      if (named.has(id))
        throw new Error(`${this.scope}: a record is named twice`);
      named.add(id);
    };
    const puts = edit.puts.map(({ id, revision, envelope }) => {
      once(id);
      const baseRevision = this.records.get(id)?.revision ?? 0;
      if (revision <= baseRevision)
        throw new Error(
          `${this.scope}: a put's revision must be above the record's`,
        );
      return { id, baseRevision, revision, envelope };
    });
    const deletes = edit.deletes.map((id) => {
      once(id);
      const stored = this.records.get(id);
      if (!stored) throw new Error(`${this.scope}: a delete names no record`);
      return { id, baseRevision: stored.revision };
    });
    return { scope: this.scope, puts, deletes };
  }

  /** The index once `batch` lands: what the next head names. */
  indexAfter(batch: RecordsBatch): [string, number][] {
    const next = new ScopeRecords(this.scope);
    for (const [id, record] of this.records) next.records.set(id, record);
    for (const put of batch.puts)
      next.records.set(put.id, {
        revision: put.revision,
        envelope: put.envelope,
      });
    for (const gone of batch.deletes) next.records.delete(gone.id);
    return next.index();
  }
}

/** The `POST /api/account/records` body. */
export function batchBody(batch: RecordsBatch, head: string): unknown {
  return {
    head,
    puts: batch.puts.map(({ id, baseRevision, envelope }) => ({
      scope: batch.scope,
      id,
      baseRevision,
      envelope,
    })),
    deletes: batch.deletes.map(({ id, baseRevision }) => ({
      scope: batch.scope,
      id,
      baseRevision,
    })),
  };
}

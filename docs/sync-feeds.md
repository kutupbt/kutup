# Change feeds

How an app keeps a copy of server state in the browser (or a native client)
current without re-reading everything: one design for every app, in
`crates/kutup-server/src/change_feed.rs`. Mail's body search is the first
user (`GET /api/mail/search-index/changes`, docs/plans/mail-body-search.md);
Drive, Contacts and the other apps' caches move onto it as they gain local
copies (docs/roadmap.md).

## The contract

- **Rows** carry `change_xid BIGINT`, the transaction that last changed them.
  A `BEFORE INSERT OR UPDATE` trigger sets it to `pg_current_xact_id()`. A
  change to a row's children (Mail: a label put on or taken off) touches
  the row, so the row is the unit of change.
- **Deletions** leave a tombstone `(owner, id, change_xid, deleted_at)`,
  written by an `AFTER DELETE` trigger, so purges, retention and account
  deletion are covered without each path remembering to.
- **Cursor:** `(xid, id)`, sent as the string `"<xid>.<uuid>"`. It is opaque
  to clients, which only store and send it back.
- **A page** holds the keys after the cursor whose `change_xid` is below the
  snapshot's xmin (`pg_snapshot_xmin(pg_current_snapshot())`), rows and
  tombstones in one `(xid, id)` order, up to a limit:
  - Every transaction below the xmin has finished, so a change committed
    late (a long transaction with a low xid) is never skipped; it shows on a
    later page instead.
  - `next` is the last key when there is more, or the xmin itself (with the
    nil id) when the page reached the present.
  - Without a cursor, the answer is just `next`: where the feed is now. A
    client takes it before building its copy, so nothing changed during the
    build is missed.
- **Floor:** tombstones are kept for a retention period (Mail: 30 days), then
  forgotten. Each owner's floor records the highest forgotten `change_xid`;
  the retention job also removes the floors of owners that no longer exist.
- **Resync:** a cursor at or below the floor, or above the current xmin, can
  no longer be answered. The page says `resync` with a fresh `next`, and the
  client builds its copy again from scratch.
  - Above the xmin means the cursor came from ahead of this database: a
    restore from backup, or another cluster where transaction ids count from
    low again. Treating it as "nothing new" would silently lose every change
    until the counter caught up.
- The response keeps HTTP 200 with `resync: true` (Mail's wire). Apps added
  later use the same shape.

## Adding a feed

1. Add `change_xid` and the trigger to the table, an index on
   `(owner, change_xid, id)`, a tombstone table and a floors table
   (migration 163 is the template).
2. Declare a `change_feed::Feed::new(…)` constant with the fixed table names
   and the owner column, plus a literal row filter if only some rows belong
   to the feed. The names are checked when the server is built.
3. The handler calls `change_feed::page` inside a transaction and loads the
   changed rows in it. Under READ COMMITTED that read may see a version
   newer than the page's keys; that is harmless, because any change after
   the page's xmin is answered again on a later page.
4. The retention job calls `change_feed::forget_tombstones`.

## Client side

- Store the cursor with the copy, in the same encrypted record.
- Apply a page atomically (rows upserted, tombstones removed), then store
  `next`.
- On `resync`, or a `400` for the cursor itself, discard the copy and build
  again. On anything else (`401`, `429`, `5xx`, network errors) keep the copy
  and retry later with the same cursor.

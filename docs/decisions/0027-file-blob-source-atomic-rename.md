# ADR-0027: `FileBlobSource` — write-fsync-rename, rebuild-from-disk, GC stale tmp

## Status

Accepted 2026-04-21.

## Context

`InMemoryBlobSource` is fine for demos but doesn't survive a restart. The
production `FileBlobSource` writes blobs to disk keyed by `transfer_id`.
A crash mid-write yields a partial file; a subsequent read of that file
would fail signature verification or return garbage. We need durable,
atomic writes and a way to clean up debris.

## Decision

`FileBlobSource` persists each blob with the classic pattern:

1. Write to `<blob_dir>/<transfer_id>.tmp`.
2. `fsync()` the file.
3. `rename()` to `<blob_dir>/<transfer_id>.bin` (atomic on POSIX).

On startup, `rebuild_from_disk()` scans `<blob_dir>` and registers any
`.bin` files in the in-memory index. `.tmp` files older than 24 h are
GC'd (`gc_stale_tmp()`), assuming they're debris from a crashed write.

## Consequences

- A crash mid-write leaves a `.tmp` that will be cleaned up next
  startup; no half-blobs ever become readable.
- Restart recovers all persisted blobs without consulting an external
  index.
- The `<blob_dir>` must be on a filesystem with working `rename()`
  atomicity — documented as a deployment prereq.
- Long-running senders accumulate `.tmp` only from crashes, never from
  normal flow.

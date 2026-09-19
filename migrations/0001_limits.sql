-- The per-client limits shared by every replica: session leases and fixed
-- windows. Written to be safe on a database that already carries these tables
-- from before migrations were tracked.

CREATE TABLE IF NOT EXISTS notary_leases (
    lease_id uuid PRIMARY KEY,
    client_key text NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS notary_leases_client_key_expires_at
    ON notary_leases (client_key, expires_at);

CREATE TABLE IF NOT EXISTS notary_windows (
    client_key text NOT NULL,
    dimension text NOT NULL,
    window_secs bigint NOT NULL,
    window_start timestamptz NOT NULL,
    units bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (client_key, dimension, window_secs, window_start)
);

-- Superseded: the sweep's predicate is on the window's END, which a
-- start-only index cannot serve.
DROP INDEX IF EXISTS notary_windows_window_start;

-- The sweep deletes windows whose end is past. Its predicate in the store
-- (src/store/postgres.rs, `window_end!`) must be this expression verbatim,
-- or Postgres scans the table; the store's EXPLAIN test holds them together.
-- `AT TIME ZONE 'UTC'` makes the expression IMMUTABLE, which an index needs;
-- plain `timestamptz + interval` is only STABLE.
CREATE INDEX IF NOT EXISTS notary_windows_ends_at
    ON notary_windows (((window_start AT TIME ZONE 'UTC') + make_interval(secs => window_secs)));

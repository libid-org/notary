-- Every window that has ended. The predicate is the expression indexed by
-- migrations/0001_limits.sql (notary_windows_ends_at) verbatim, so the planner
-- uses the index; the store's EXPLAIN test holds the two together.
DELETE FROM notary_windows
WHERE ((window_start AT TIME ZONE 'UTC') + make_interval(secs => window_secs)) < (now() AT TIME ZONE 'UTC')

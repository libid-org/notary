-- The window $3 seconds long that the database's now() falls in: fixed
-- windows, so every replica computes the same key.
SELECT units FROM notary_windows
WHERE client_key = $1 AND dimension = $2 AND window_secs = $3
  AND window_start = to_timestamp(floor(extract(epoch FROM now()) / $3) * $3)

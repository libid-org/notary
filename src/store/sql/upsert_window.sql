INSERT INTO notary_windows (client_key, dimension, window_secs, window_start, units)
VALUES ($1, $2, $3, to_timestamp(floor(extract(epoch FROM now()) / $3) * $3), $4)
ON CONFLICT (client_key, dimension, window_secs, window_start)
DO UPDATE SET units = notary_windows.units + EXCLUDED.units

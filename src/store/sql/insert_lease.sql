INSERT INTO notary_leases (lease_id, client_key, expires_at)
VALUES ($1, $2, now() + make_interval(secs => $3))

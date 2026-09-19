SELECT count(*) FROM notary_leases WHERE client_key = $1 AND expires_at > now()

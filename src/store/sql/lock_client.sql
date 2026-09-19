-- One client's counts change under one lock: two racers would both see room.
SELECT pg_advisory_xact_lock(hashtext($1)::bigint)

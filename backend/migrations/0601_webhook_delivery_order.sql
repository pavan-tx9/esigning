-- Integration. `webhook_deliveries` had nothing to order by except `next_attempt_at`, and two
-- events queued in the same instant (`envelope.completed` and `envelope.sealed`, when the inline
-- seal succeeds) tie on it. A host should hear "completed" before "sealed" whenever nothing has
-- failed, so deliveries get an insertion sequence. Ordering is still best effort once a delivery
-- has been retried; the payload's `occurred_at` and `status` are what a host should trust.
ALTER TABLE webhook_deliveries ADD COLUMN seq bigserial;
CREATE INDEX webhook_deliveries_due ON webhook_deliveries (next_attempt_at, seq) WHERE delivered_at IS NULL;
GRANT USAGE, SELECT ON SEQUENCE webhook_deliveries_seq_seq TO esign_app;

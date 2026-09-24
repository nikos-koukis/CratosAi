-- Dynamically registered clients may expire (RFC 7591 client_secret_expires_at);
-- NULL means never.
ALTER TABLE oauth_clients ADD COLUMN secret_expires_at timestamptz;

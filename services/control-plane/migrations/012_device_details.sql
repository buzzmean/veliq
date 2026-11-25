DO $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=12) THEN
  CREATE TABLE device_details (
   device_id text PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
   computer_name text NOT NULL CHECK (length(computer_name) BETWEEN 1 AND 128),
   software_version text NOT NULL DEFAULT '' CHECK (length(software_version)<=80),
   observed_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE account_device_labels (
   account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
   machine_hash text NOT NULL,
   label text NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
   updated_at timestamptz NOT NULL DEFAULT now(),
   PRIMARY KEY(account_id,machine_hash)
  );
  INSERT INTO schema_migrations(version) VALUES(12);
 END IF;
END $$;

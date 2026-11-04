PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vbv_parties (
  code TEXT PRIMARY KEY NOT NULL,
  host_member_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vbv_party_members (
  id TEXT PRIMARY KEY NOT NULL,
  party_code TEXT NOT NULL,
  player_name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  joined_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  FOREIGN KEY (party_code) REFERENCES vbv_parties(code) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS vbv_party_members_name_unique
  ON vbv_party_members (party_code, lower(player_name));

CREATE INDEX IF NOT EXISTS vbv_party_members_party
  ON vbv_party_members (party_code, joined_at);

CREATE INDEX IF NOT EXISTS vbv_party_members_last_seen
  ON vbv_party_members (party_code, last_seen);

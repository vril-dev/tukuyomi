ALTER TABLE center_remote_ssh_sessions
    ADD COLUMN operator_mode TEXT NOT NULL DEFAULT 'cli';

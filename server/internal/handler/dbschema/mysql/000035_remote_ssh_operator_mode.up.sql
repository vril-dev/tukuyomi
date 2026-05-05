ALTER TABLE center_remote_ssh_sessions
    ADD COLUMN operator_mode VARCHAR(16) NOT NULL DEFAULT 'cli' AFTER status;

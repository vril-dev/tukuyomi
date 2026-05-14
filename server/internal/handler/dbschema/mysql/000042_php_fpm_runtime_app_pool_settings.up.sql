ALTER TABLE vhosts ADD COLUMN php_fpm_pool_settings TEXT NULL;
UPDATE vhosts SET php_fpm_pool_settings = '' WHERE php_fpm_pool_settings IS NULL;
ALTER TABLE vhosts MODIFY COLUMN php_fpm_pool_settings TEXT NOT NULL;

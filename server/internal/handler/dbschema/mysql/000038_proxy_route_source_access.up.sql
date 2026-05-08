CREATE TABLE IF NOT EXISTS proxy_route_access_cidrs (
	version_id BIGINT NOT NULL,
	route_kind VARCHAR(32) NOT NULL,
	route_position BIGINT NOT NULL,
	list_kind VARCHAR(16) NOT NULL,
	position BIGINT NOT NULL,
	cidr VARCHAR(128) NOT NULL,
	PRIMARY KEY(version_id, route_kind, route_position, list_kind, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

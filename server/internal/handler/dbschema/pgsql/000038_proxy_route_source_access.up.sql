CREATE TABLE IF NOT EXISTS proxy_route_access_cidrs (
	version_id BIGINT NOT NULL,
	route_kind TEXT NOT NULL,
	route_position BIGINT NOT NULL,
	list_kind TEXT NOT NULL,
	position BIGINT NOT NULL,
	cidr TEXT NOT NULL,
	PRIMARY KEY(version_id, route_kind, route_position, list_kind, position)
);

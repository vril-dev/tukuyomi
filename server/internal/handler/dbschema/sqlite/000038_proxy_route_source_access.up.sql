CREATE TABLE IF NOT EXISTS proxy_route_access_cidrs (
	version_id INTEGER NOT NULL,
	route_kind TEXT NOT NULL,
	route_position INTEGER NOT NULL,
	list_kind TEXT NOT NULL,
	position INTEGER NOT NULL,
	cidr TEXT NOT NULL,
	PRIMARY KEY(version_id, route_kind, route_position, list_kind, position)
);

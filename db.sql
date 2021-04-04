-- Postgres Base Table Structure

CREATE USER coredns;
CREATE DATABASE coredns OWNER coredns;

CREATE TABLE zones (
	id 			SERIAL PRIMARY KEY,
	created_at	timestamp with time zone,
	updated_at	timestamp with time zone,
	deleted_at	timestamp with time zone,

	disabled	boolean,

	name 		varchar(65536)
);


CREATE TABLE soa_records (
	id 			SERIAL PRIMARY KEY,
	created_at	timestamp with time zone,
	updated_at	timestamp with time zone,
	deleted_at	timestamp with time zone,

	disabled	boolean,

	zone_id 	bigint references zones(id),

	name 		varchar(255),
	ttl 		int,

	ns 			varchar(255),
	mbox        varchar(255),
	serial 		bigint,
	refresh 	bigint,
	retry 		bigint,
	expire 		bigint,
	minttl      bigint
);

CREATE TABLE a_records (
	id 			SERIAL PRIMARY KEY,
	created_at	timestamp with time zone,
	updated_at	timestamp with time zone,
	deleted_at	timestamp with time zone,

	disabled	boolean,

	zone_id 	bigint references zones(id),

	name 		varchar(255),
	ttl 		int,

	a 			inet
);

CREATE TABLE aaaa_records (
	id 			SERIAL PRIMARY KEY,
	created_at	timestamp with time zone,
	updated_at	timestamp with time zone,
	deleted_at	timestamp with time zone,

	disabled	boolean,

	zone_id 	bigint references zones(id),

	name 		varchar(255),
	ttl 		int,

	aaaa		inet
);

CREATE TABLE mx_records (
	id 			SERIAL PRIMARY KEY,
	created_at	timestamp with time zone,
	updated_at	timestamp with time zone,
	deleted_at	timestamp with time zone,

	disabled	boolean,

	zone_id 	bigint references zones(id),

	name 		varchar(255),
	ttl 		int,

	preference  int,
	mx 			varchar(65536)
);

CREATE TABLE ptr_records (
	id 			SERIAL PRIMARY KEY,
	created_at	timestamp with time zone,
	updated_at	timestamp with time zone,
	deleted_at	timestamp with time zone,

	disabled	boolean,

	zone_id 	bigint references zones(id),

	name 		varchar(255),
	ttl 		int,

	ptr 		varchar(65536)
);

CREATE TABLE cname_records (
	id 			SERIAL PRIMARY KEY,
	created_at	timestamp with time zone,
	updated_at	timestamp with time zone,
	deleted_at	timestamp with time zone,

	disabled	boolean,

	zone_id 	bigint references zones(id),

	name 		varchar(255),
	ttl 		int,

	target 		varchar(65536)
);


CREATE TABLE ns_records (
	id 			SERIAL PRIMARY KEY,
	created_at	timestamp with time zone,
	updated_at	timestamp with time zone,
	deleted_at	timestamp with time zone,

	disabled	boolean,

	zone_id 	bigint references zones(id),

	name 		varchar(255),
	ttl 		int,

	ns 			varchar(65536)
);

CREATE TABLE srv_records (
	id 			SERIAL PRIMARY KEY,
	created_at	timestamp with time zone,
	updated_at	timestamp with time zone,
	deleted_at	timestamp with time zone,

	disabled	boolean,

	zone_id 	bigint references zones(id),

	name 		varchar(255),
	ttl 		int,

	priority    int,
	weight 		int,
	port 		int,
	target      varchar(255)
);

CREATE TABLE txt_records (
	id 			SERIAL PRIMARY KEY,
	created_at	timestamp with time zone,
	updated_at	timestamp with time zone,
	deleted_at	timestamp with time zone,

	disabled	boolean,

	zone_id 	bigint references zones(id),

	name 		varchar(255),
	ttl 		int,

	txt 		varchar(65536)
);

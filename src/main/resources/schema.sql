pragma journal_mode = wal;
pragma synchronous = normal;

create table if not exists source(
  name text not null primary key
, license text
, url text
);

create table if not exists source_metadata(
  source_name text not null
, key text not null
, value text not null
, created_at integer not null default (unixepoch())
, updated_at integer
, primary key(source_name, key)
, foreign key(source_name) references source(name)
);

create table if not exists vuln(
  id text not null primary key
);

create table if not exists vuln_alias(
  source_name text not null -- Name of the source claiming this alias.
, vuln_id text not null -- ID of the vulnerability being aliased.
, alias_id text not null -- ID of the aliasing vulnerability.
, created_at integer not null default (unixepoch()) -- When the record was created in the database.
, deleted_at integer -- When the record was deleted in the database (i.e. no longer reported by the source).
, primary key(source_name, vuln_id, alias_id)
, foreign key(source_name) references source(name)
, foreign key(vuln_id) references vuln(id)
);

-- Vulnerability data as provided by a source.
create table if not exists vuln_data(
  source_name text not null -- Name of the source providing this data.
, vuln_id text not null -- ID of the vulnerability being described.
, description text
, cwes text -- JSON array of CWE IDs.
, source_created_at integer -- When the record was created in the source.
, source_published_at integer -- When the record was published by the source.
, source_updated_at integer -- When the record was updated in the source.
, source_rejected_at integer -- When the record was rejected in the source.
, created_at integer not null default (unixepoch()) -- When the record was created in the database.
, updated_at integer -- When the record was updated in the database.
, primary key(source_name, vuln_id)
, foreign key(source_name) references source(name)
, foreign key(vuln_id) references vuln(id)
);

-- https://cyclonedx.org/docs/1.6/json/#vulnerabilities_items_ratings
create table if not exists vuln_rating(
  source_name text not null
, vuln_id text not null
, method text not null
, severity text not null
, vector text
, score real
, created_at integer not null default (unixepoch()) -- When the record was created in the database.
, updated_at integer -- When the record was updated in the database.
, primary key(source_name, vuln_id, method)
, foreign key(source_name) references source(name)
, foreign key(vuln_id) references vuln(id)
, check(method in ('CVSSv2', 'CVSSv3', 'CVSSv3.1', 'CVSSv4'))
, check(severity in ('critical', 'high', 'medium', 'low', 'info', 'none', 'unknown'))
);

create table if not exists vuln_reference(
  source_name text not null -- Name of the source providing this data.
, vuln_id text not null -- ID of the vulnerability the references are for.
, url text not null -- URL of the reference.
, name text -- Human friendly name of the reference.
, primary key(source_name, vuln_id, name)
, foreign key(source_name) references source(name)
, foreign key(vuln_id) references vuln(id)
);

create table if not exists matching_criteria(
  id integer not null primary key autoincrement
, source_name text not null
, vuln_id text not null
, cpe text -- Full CPE.
, cpe_part text -- "Part" portion of the CPE in (lowercase).
, cpe_vendor text -- "Vendor" portion of the CPE in (lowercase).
, cpe_product text -- "Product" portion of the CPE (lowercase).
, purl_type text -- "Type" portion of the PURL.
, purl_namespace text -- "Namespace" portion of the PURL.
, purl_name text -- "Name" portion of the PURL.
, versions text -- Versions to match in vers notation.
, additional_criteria_type text -- Discriminator for the type in additional_criteria.
, additional_criteria blob -- Additional criteria such as symbols, call stacks.
, created_at integer not null default (unixepoch()) -- When the record was created in the database.
, updated_at integer -- When the record was updated in the database.
, foreign key(source_name) references source(name)
, foreign key(vuln_id) references vuln(id)
-- CPE matching is case-insensitive. Ensure CPE portions are stored in lowercase.
, check(cpe_part = lower(cpe_part) and cpe_vendor = lower(cpe_vendor) and cpe_product = lower(cpe_product))
-- Ensure versions are provided in vers notation.
, check(case when versions is not null then versions like 'vers:%' end)
-- When additional criteria is provided, a type discriminator must be set.
, check(case when additional_criteria is not null then additional_criteria_type is not null end)
);

create index if not exists matching_criteria_source_name_vuln_id_idx
    on matching_criteria(source_name, vuln_id);
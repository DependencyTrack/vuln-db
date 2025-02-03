# vuln-db

[![License](http://img.shields.io/:license-apache-brightgreen.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

Proof of concept for OWASP Dependency-Track's own, centralized vulnerability database.

Refer to https://github.com/DependencyTrack/dependency-track/issues/4122 for details.

## Usage

### Importing

```shell
docker run -it --rm \
  -e 'GH_TOKEN=<your_github_token>' \
  -e 'NVD_TOKEN=<your_nvd_token>' \
  -v "$(pwd):/workspace" \
  -w '/workspace' \
  ghcr.io/nscuro/vuln-db:snapshot \
  import GitHub NVD OSV
```

This will populate the following database files in parallel:

* `GitHub.sqlite`
* `NVD.sqlite`
* `OSV.sqlite`

### Merging

```shell
docker run -it --rm \
  -v "$(pwd):/workspace" \
  -w '/workspace' \
  ghcr.io/nscuro/vuln-db:snapshot \
  merge --output=All.sqlite GitHub.sqlite NVD.sqlite OSV.sqlite
```

### Compressing

Databases should be compressed before distributing them, to save storage and network costs.

```shell
docker run -it --rm \
  -v "$(pwd):/workspace" \
  -w '/workspace' \
  ghcr.io/nscuro/vuln-db:snapshot \
  compress --output=All.sqlite.zstd --level=11 Merged.sqlite
```

### Scanning

To get a rough idea of the data quality in a database, it can be leveraged
to scan a CycloneDX Bill of Materials. The implementation of this command
is also intended to showcase how matching logic may work.

```shell
docker run -it --rm \
  -v "$(pwd):/workspace" \
  -w '/workspace' \
  ghcr.io/nscuro/vuln-db:snapshot \
  scan --database=All.sqlite bom.json
```

## Research

The database can be used to conduct research on the data across multiple sources.

### Aliases

To find the aliases of all CVEs, and which source reported them:

```sql
with cve_aliases as(
  select vuln_id
       , alias_id
       , source_name
    from vuln_alias
   where vuln_id like 'CVE-%'
   union
  select alias_id as vuln_id
       , vuln_id as alias_id
       , source_name
    from vuln_alias
   where alias_id like 'CVE-%'
)
select *
  from cve_aliases
 order by vuln_id desc
 limit 5
```

Example output:

| vuln\_id       | alias\_id           | source\_name |
|:---------------|:--------------------|:-------------|
| CVE-2025-24891 | GHSA-24f2-fv38-3274 | OSV          |
| CVE-2025-24884 | GHSA-hcr5-wv4p-h2g2 | GitHub       |
| CVE-2025-24884 | GHSA-hcr5-wv4p-h2g2 | OSV          |
| CVE-2025-24883 | GHSA-q26p-9cq4-7fc2 | GitHub       |
| CVE-2025-24883 | GHSA-q26p-9cq4-7fc2 | OSV          |

This data could be used to calculate confidences for alias relationships,
i.e. the more sources report it the higher the confidence.

### Withdrawal across aliases

Vulnerabilities can be withdrawn or rejected. Taking aliases into consideration,
is withdrawal consistently declared in all sources?

```sql
with
rejected_vulns as(
  select vuln_id
       , source_name
       , source_rejected_at
    from vuln_data
   where source_rejected_at is not null
),
rejected_vuln_aliases as(
  select vuln_id
       , alias_id
    from vuln_alias
   where vuln_id in (select vuln_id from rejected_vulns)
),
rejected_aliases as(
  select vuln_data.vuln_id as vuln_id
       , rejected_vuln_aliases.vuln_id as aliased_vuln_id
       , source_name
       , source_rejected_at
    from vuln_data
   inner join rejected_vuln_aliases
      on rejected_vuln_aliases.alias_id = vuln_data.vuln_id
)
select vuln_id
     , null as alias_id
     , source_name
     , source_rejected_at
  from rejected_vulns
 where vuln_id in (select aliased_vuln_id from rejected_aliases)
 union all
select aliased_vuln_id as vuln_id
     , vuln_id as alias_id
     , source_name
     , source_rejected_at
  from rejected_aliases
 order by vuln_id, alias_id nulls first
```

Example output:

| vuln\_id       | alias\_id           | source\_name | source\_rejected\_at |
|:---------------|:--------------------|:-------------|:---------------------|
| CVE-2018-1103  | null                | OSV          | 1715751224000        |
| CVE-2018-1103  | GHSA-w55j-f7vx-6q37 | GitHub       | null                 |
| CVE-2018-1103  | GHSA-w55j-f7vx-6q37 | OSV          | null                 |
| CVE-2018-1103  | GO-2020-0026        | OSV          | null                 |
| CVE-2018-11087 | null                | OSV          | 1715751224000        |
| CVE-2018-11087 | GHSA-w4g2-9hj6-5472 | GitHub       | null                 |
| CVE-2018-11087 | GHSA-w4g2-9hj6-5472 | OSV          | null                 |

In the above output `CVE-2018-11087` and `CVE-2018-11087` are both declared as withdrawn
by OSV, but none of their respective aliases are, even if they originate from the same source (OSV).
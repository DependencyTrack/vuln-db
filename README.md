# vuln-db

[![License](http://img.shields.io/:license-apache-brightgreen.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

Proof of concept for OWASP Dependency-Track's own, centralized vulnerability database.

Refer to https://github.com/DependencyTrack/dependency-track/issues/4122 for details.

## Usage

> [!NOTE]
> *vuln-db* requires Java >= 21.

### Importing

```shell
# Required for GitHub
export GH_TOKEN='<your_github_token>'

# Optional for NVD. Import will be slower without it.
export NVD_TOKEN='<your_nvd_token>'

mvn compile exec:java \
  -Dexec.mainClass=org.dependencytrack.vulndb.Application \
  -Dexec.args='import GitHub NVD OSV'
```

This will populate the following database files in parallel:

* `GitHub.sqlite`
* `NVD.sqlite`
* `OSV.sqlite`

### Merging

```shell
mvn compile exec:java \
  -Dexec.mainClass=org.dependencytrack.vulndb.Application \
  -Dexec.args='merge -output=Merged.sqlite GitHub.sqlite NVD.sqlite OSV.sqlite'
```

### Compressing

Databases should be compressed before distributing them, to save storage and network costs.

```shell
mvn compile exec:java \
  -Dexec.mainClass=org.dependencytrack.vulndb.Application \
  -Dexec.args='compress -output=Merged.sqlite.zstd -level 11 Merged.sqlite'
```

### Scanning

To get a rough idea of the data quality in a database, it can be leveraged
to scan a CycloneDX Bill of Materials. The implementation of this command
is also intended to showcase how matching logic may work.

```shell
mvn compile exec:java \
  -Dexec.mainClass=org.dependencytrack.vulndb.Application \
  -Dexec.args="scan -database merged.sqlite ./bom.json"
```

## Research

The database can be used to conduct research on the data across multiple sources.

### Aliases

To find the aliases of all CVEs, and which source reported them:

```sql
with cve_aliases as(
  select vuln.id as vuln_id
       , vuln_alias.alias_id as alias_id
       , vuln_alias.source_name as alias_source
    from vuln
   inner join vuln_alias
      on vuln_alias.vuln_id = vuln.id
   where vuln.id like 'CVE-%'
   union
  select vuln.id as vuln_id
       , vuln_alias.vuln_id as alias_id
       , vuln_alias.source_name as alias_source
    from vuln
   inner join vuln_alias
      on vuln_alias.alias_id = vuln.id
   where vuln.id like 'CVE-%'
)
select *
  from cve_aliases
 order by vuln_id desc
 limit 5
```

Example output:

| vuln\_id       | alias\_id           | alias\_source |
|:---------------|:--------------------|:--------------|
| CVE-2025-24891 | GHSA-24f2-fv38-3274 | OSV           |
| CVE-2025-24884 | GHSA-hcr5-wv4p-h2g2 | GitHub        |
| CVE-2025-24884 | GHSA-hcr5-wv4p-h2g2 | OSV           |
| CVE-2025-24883 | GHSA-q26p-9cq4-7fc2 | GitHub        |
| CVE-2025-24883 | GHSA-q26p-9cq4-7fc2 | OSV           |

This data could be used to calculate confidences for alias relationships,
i.e. the more sources report it the higher the confidence.
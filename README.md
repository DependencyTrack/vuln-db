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
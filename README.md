# vuln-db

[![License](http://img.shields.io/:license-apache-brightgreen.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

Proof of concept for OWASP Dependency-Track's own, centralized vulnerability database.

Refer to https://github.com/DependencyTrack/dependency-track/issues/4122 for details.

## Usage

```shell
mvn compile exec:java \
  -Dexec.mainClass=org.dependencytrack.vulndb.Application \
  -Dexec.args='import -source NVD -source OSV'
```

> [!NOTE]
> *vuln-db* requires Java >= 21.

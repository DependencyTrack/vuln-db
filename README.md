# vuln-db

[![License](http://img.shields.io/:license-apache-brightgreen.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

Proof of concept for OWASP Dependency-Track's own, centralized vulnerability database.

Refer to https://github.com/DependencyTrack/dependency-track/issues/4122 for details.

## Usage

```shell
mvn clean package -DskipTests
export GH_TOKEN='<your_github_token>'
java -jar ./target/vuln-db-1.0.0-SNAPSHOT.jar
```

> [!NOTE]
> *vuln-db* requires Java >= 21.

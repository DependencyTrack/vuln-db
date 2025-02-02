FROM eclipse-temurin:21-jre-alpine
WORKDIR /opt/owasp/dependency-track
COPY --chmod=440 ./target/vuln-db-*-jar-with-dependencies.jar ./vuln-db.jar
ENTRYPOINT ["java", "-jar", "/opt/owasp/dependency-track/vuln-db.jar"]
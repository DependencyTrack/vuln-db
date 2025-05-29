package org.dependencytrack.vulndb.source.euvd;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.vulndb.api.Database;
import org.dependencytrack.vulndb.api.Importer;
import org.dependencytrack.vulndb.api.Reference;
import org.dependencytrack.vulndb.api.Source;
import org.dependencytrack.vulndb.api.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.ZoneOffset;
import java.util.List;

public final class EuvdImporter implements Importer {

    private static final Logger LOGGER = LoggerFactory.getLogger(EuvdImporter.class);

    private Database database;
    private HttpClient httpClient;
    private ObjectMapper objectMapper;

    @Override
    public Source source() {
        return new Source("euvd", "European Union Vulnerability Database", null, "https://euvd.enisa.europa.eu/");
    }

    @Override
    public void init(final Database database) {
        this.database = database;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .registerModule(new JavaTimeModule());
    }

    @Override
    public void runImport() throws Exception {
        boolean hasMore;
        int pageNumber = 0;
        int vulnsImported = 0;
        do {
            final HttpResponse<byte[]> response = httpClient.send(
                    HttpRequest.newBuilder(URI.create(
                                    "https://euvdservices.enisa.europa.eu/api/vulnerabilities?size=100&page=%d".formatted(pageNumber)))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                throw new Exception("Unexpected response code: " + response.statusCode());
            }

            final var vulnsPage = objectMapper.readValue(response.body(), EuvdVulnerabilitiesPage.class);
            final List<Vulnerability> vulns = vulnsPage.items().stream()
                    .map(this::convert)
                    .toList();

            database.storeVulnerabilities(vulns);

            vulnsImported += vulns.size();
            hasMore = vulnsImported < vulnsPage.total();
            LOGGER.info("Imported {}/{} vulnerabilities", vulnsImported, vulnsPage.total());
        } while (hasMore);
    }

    private Vulnerability convert(final EuvdVulnerability euvdVuln) {
        // TODO: Covert baseScore* values to Rating records.

        return new Vulnerability(
                euvdVuln.id(),
                euvdVuln.aliases(),
                null,
                euvdVuln.description(),
                null,
                null,
                euvdVuln.references() != null
                        ? euvdVuln.references().stream().map(referenceUrl -> new Reference(referenceUrl, null)).toList()
                        : null,
                null,
                null,
                euvdVuln.datePublished().toInstant(ZoneOffset.UTC),
                euvdVuln.dateUpdated().toInstant(ZoneOffset.UTC),
                null);
    }

}

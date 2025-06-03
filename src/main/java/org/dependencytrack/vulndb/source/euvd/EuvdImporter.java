package org.dependencytrack.vulndb.source.euvd;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import org.dependencytrack.vulndb.api.Database;
import org.dependencytrack.vulndb.api.Importer;
import org.dependencytrack.vulndb.api.Rating;
import org.dependencytrack.vulndb.api.Reference;
import org.dependencytrack.vulndb.api.Source;
import org.dependencytrack.vulndb.api.Vulnerability;
import org.metaeffekt.core.security.cvss.CvssVector;
import org.metaeffekt.core.security.cvss.v2.Cvss2;
import org.metaeffekt.core.security.cvss.v3.Cvss3;
import org.metaeffekt.core.security.cvss.v4P0.Cvss4P0;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialRandomBackoff;

public final class EuvdImporter implements Importer {

    private static final Logger LOGGER = LoggerFactory.getLogger(EuvdImporter.class);

    private Database database;
    private HttpClient httpClient;
    private ObjectMapper objectMapper;
    private Retry retry;

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
        this.retry = RetryRegistry.of(
                        RetryConfig.<HttpResponse<?>>custom()
                                .retryOnResult(response -> response.statusCode() == 403)
                                .intervalFunction(ofExponentialRandomBackoff(
                                        Duration.ofSeconds(15),
                                        /* multiplier */ 2.0,
                                        /* randomizationFactor */ 0.5,
                                        Duration.ofMinutes(3)))
                                .maxAttempts(12)
                                .build())
                .retry("euvd-api");
        this.retry.getEventPublisher().onRetry(
                event -> LOGGER.warn(
                        "Performing retry attempt {} in {}",
                        event.getNumberOfRetryAttempts(),
                        event.getWaitInterval()));
    }

    @Override
    public void runImport() throws Exception {
        boolean hasMore;
        int pageNumber = 0;
        int vulnsImported = 0;
        do {
            final HttpResponse<byte[]> response = retry.executeCallable(
                    () -> httpClient.send(
                            HttpRequest.newBuilder(URI.create(
                                            "https://euvdservices.enisa.europa.eu/api/search?size=100&page=%d".formatted(pageNumber)))
                                    .GET()
                                    .header("User-Agent", "github.com/DependencyTrack/vuln-db")
                                    .build(),
                            HttpResponse.BodyHandlers.ofByteArray()));
            if (response.statusCode() != 200) {
                throw new Exception("Unexpected response code: " + response.statusCode());
            }

            final var vulnsPage = objectMapper.readValue(response.body(), EuvdVulnerabilitiesPage.class);
            final List<Vulnerability> vulns = vulnsPage.items().stream()
                    .map(euvdVuln -> {
                        try (var ignored = MDC.putCloseable("vulnId", euvdVuln.id())) {
                            return convert(euvdVuln);
                        }
                    })
                    .toList();

            database.storeVulnerabilities(vulns);

            vulnsImported += vulns.size();
            hasMore = vulnsImported < vulnsPage.total();
            LOGGER.info("Imported {}/{} vulnerabilities", vulnsImported, vulnsPage.total());
        } while (hasMore);
    }

    private Vulnerability convert(final EuvdVulnerability euvdVuln) {
        return new Vulnerability(
                euvdVuln.id(),
                euvdVuln.aliases(),
                /* related */ null,
                euvdVuln.description(),
                /* cwes */ null,
                getRatings(euvdVuln),
                euvdVuln.references() != null
                        ? euvdVuln.references().stream().map(referenceUrl -> new Reference(referenceUrl, null)).toList()
                        : null,
                /* matchingCriteria */ null,
                /* createdAt */ null,
                euvdVuln.datePublished() != null ? euvdVuln.datePublished().toInstant() : null,
                euvdVuln.dateUpdated() != null ? euvdVuln.dateUpdated().toInstant() : null,
                /* rejectedAt */ null);
    }

    private List<Rating> getRatings(final EuvdVulnerability euvdVuln) {
        if (euvdVuln.baseScoreVector() == null) {
            return null;
        }

        final CvssVector vector = CvssVector.parseVector(euvdVuln.baseScoreVector());
        if (vector != null) {
            final Rating.Method method = switch (vector) {
                case Cvss2 ignored -> Rating.Method.CVSSv2;
                case Cvss3 ignored -> Rating.Method.CVSSv3;
                case Cvss4P0 ignored -> Rating.Method.CVSSv4;
                default -> null;
            };
            if (method == null) {
                LOGGER.warn("Unexpected CVSS type {}", vector.getClass().getName());
            }

            return List.of(
                    new Rating(
                            method,
                            Rating.Severity.ofCvss(vector),
                            vector.toString(),
                            vector.getBaseScore()));
        } else {
            LOGGER.warn("Failed to parse CVSS vector {}", euvdVuln.baseScoreVector());
        }

        return null;
    }

}

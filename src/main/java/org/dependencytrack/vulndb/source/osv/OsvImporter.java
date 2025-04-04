package org.dependencytrack.vulndb.source.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersUtils;
import org.dependencytrack.vulndb.api.Database;
import org.dependencytrack.vulndb.api.Importer;
import org.dependencytrack.vulndb.api.MatchingCriteria;
import org.dependencytrack.vulndb.api.Rating;
import org.dependencytrack.vulndb.api.Source;
import org.dependencytrack.vulndb.api.Vulnerability;
import org.metaeffekt.core.security.cvss.CvssVector;
import org.metaeffekt.core.security.cvss.v2.Cvss2;
import org.metaeffekt.core.security.cvss.v3.Cvss3;
import org.metaeffekt.core.security.cvss.v4P0.Cvss4P0;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static java.util.function.Predicate.not;

public final class OsvImporter implements Importer {

    private static final Logger LOGGER = LoggerFactory.getLogger(OsvImporter.class);

    // TODO: Make this configurable.
    private static final Set<String> ENABLED_ECOSYSTEMS = Set.of(
            "Debian",
            "Go",
            "Maven",
            "npm");

    private Database database;
    private HttpClient httpClient;
    private ObjectMapper objectMapper;

    @Override
    public Source source() {
        return new Source("osv", "Open Source Vulnerabilities (OSV)", null, "https://osv.dev/");
    }

    @Override
    public void init(final Database database) {
        this.database = database;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule());
    }

    @Override
    public void runImport() throws Exception {
        final List<String> availableEcosystems = getAvailableEcosystems();
        LOGGER.info("Available ecosystems: {}", availableEcosystems);

        for (final String ecosystem : availableEcosystems) {
            if (!ENABLED_ECOSYSTEMS.contains(ecosystem)) {
                LOGGER.info("Skipping ecosystem {}", ecosystem);
                continue;
            }

            LOGGER.info("Downloading archive of ecosystem {}", ecosystem);
            final Path ecosystemArchivePath = downloadEcosystemArchive(ecosystem);

            LOGGER.info("Processing advisories of ecosystem {}", ecosystem);
            extractEcosystemArchive(ecosystemArchivePath, advisory -> {
                try (var ignored = MDC.putCloseable("vulnId", advisory.id())) {
                    processAdvisory(advisory);
                }
            });
        }
    }

    private List<String> getAvailableEcosystems() throws InterruptedException, IOException {
        final HttpResponse<Stream<String>> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(
                                "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofLines());
        if (response.statusCode() != 200) {
            throw new IOException("Unexpected response code: " + response.statusCode());
        }

        return response.body()
                .map(String::trim)
                .filter(not(String::isEmpty))
                .sorted()
                .collect(Collectors.toList());
    }

    private Path downloadEcosystemArchive(final String ecosystem) throws InterruptedException, IOException {
        final Path tempFile = Files.createTempFile(null, ".zip");
        tempFile.toFile().deleteOnExit();

        final String encodedEcosystem = URLEncoder.encode(ecosystem, StandardCharsets.UTF_8).replace("+", "%20");

        final HttpResponse<Path> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(
                                "https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip".formatted(encodedEcosystem)))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofFile(tempFile, StandardOpenOption.WRITE));
        if (response.statusCode() != 200) {
            throw new IOException("Unexpected response code: " + response.statusCode());
        }

        return response.body();
    }

    private void extractEcosystemArchive(
            final Path archivePath,
            final Consumer<OsvAdvisory> advisoryConsumer) throws IOException {
        try (final var zipFile = new ZipFile(archivePath.toFile())) {
            final Enumeration<? extends ZipEntry> zipEntries = zipFile.entries();
            while (zipEntries.hasMoreElements()) {
                final ZipEntry entry = zipEntries.nextElement();

                try (final InputStream entryInputStream = zipFile.getInputStream(entry)) {
                    final var advisory = objectMapper.readValue(entryInputStream, OsvAdvisory.class);
                    advisoryConsumer.accept(advisory);
                }
            }
        }
    }

    private void processAdvisory(final OsvAdvisory advisory) {
        final var matchingCriteriaList = new ArrayList<MatchingCriteria>();
        if (advisory.affected() != null) {
            for (final OsvAdvisory.Affected affected : advisory.affected()) {
                if (affected.pkg() == null || affected.pkg().purl() == null) {
                    LOGGER.debug("No package information; Skipping  {}", affected);
                    continue;
                }

                final PackageURL purl;
                try {
                    purl = new PackageURL(affected.pkg().purl());
                } catch (MalformedPackageURLException e) {
                    LOGGER.warn("Encountered invalid PURL; Skipping {}", affected);
                    continue;
                }

                String additionalCriteriaType = null;
                byte[] additionalCriteria = null;
                if ("go".equalsIgnoreCase(affected.pkg().ecosystem())
                    && affected.ecosystemSpecific() != null
                    && affected.ecosystemSpecific().containsKey("imports")) {
                    final Object imports = affected.ecosystemSpecific().get("imports");
                    try {
                        additionalCriteria = objectMapper.writeValueAsBytes(imports);
                        additionalCriteriaType = "go-imports"; // TODO: Define proper naming taxonomy?
                    } catch (IOException e) {
                        LOGGER.warn("Failed to serialize go-imports {}", imports, e);
                    }
                } else if (affected.pkg().ecosystem().toLowerCase().startsWith("debian")) {
                    final String[] ecosystemParts = affected.pkg().ecosystem().split(":", 2);
                    if (ecosystemParts.length == 2) {
                        // TODO: Should be a JSON object to make it less ambiguous.
                        // TODO: Can this be generalized? Do we need this for RedHat etc. too?
                        additionalCriteria = ecosystemParts[1].trim().getBytes();
                        additionalCriteriaType = "debian-version";
                    }
                }

                if (affected.ranges() != null) {
                    for (final OsvAdvisory.Range range : affected.ranges()) {
                        try {
                            final Vers vers = VersUtils.versFromOsvRange(
                                    range.type(),
                                    affected.pkg().ecosystem(),
                                    range.genericEvents(),
                                    range.databaseSpecific());

                            matchingCriteriaList.add(new MatchingCriteria(
                                    null,
                                    purl,
                                    vers,
                                    additionalCriteriaType,
                                    additionalCriteria));
                        } catch (RuntimeException e) {
                            LOGGER.warn("Failed to build vers for {}", range, e);
                        }
                    }
                }
            }
        }

        final var ratings = new ArrayList<Rating>();
        if (advisory.severity() != null) {
            for (final OsvAdvisory.Severity severity : advisory.severity()) {
                if (severity.type() == null
                    || !severity.type().toLowerCase().startsWith("cvss")) {
                    LOGGER.warn("Unrecognized severity: {}", severity);
                    continue;
                }

                final var vector = CvssVector.parseVector(severity.score());
                if (vector != null) {
                    final Rating.Method method = switch (vector) {
                        case Cvss2 ignored -> Rating.Method.CVSSv2;
                        case Cvss3 ignored -> Rating.Method.CVSSv3;
                        case Cvss4P0 ignored -> Rating.Method.CVSSv4;
                        default -> null;
                    };
                    if (method == null) {
                        LOGGER.warn("Unexpected CVSS type {}", vector.getClass().getName());
                        continue;
                    }

                    ratings.add(new Rating(
                            method,
                            Rating.Severity.ofCvss(vector),
                            vector.toString(),
                            vector.getBaseScore()));
                } else {
                    LOGGER.warn("Failed to parse CVSS vector {}", severity.score());
                }
            }
        }

        final var cwes = new ArrayList<Integer>();
        if (advisory.databaseSpecific() != null
            && advisory.databaseSpecific().containsKey("cwe_ids")) {
            final Collection<String> cweIds;
            try {
                cweIds = (Collection<String>) advisory.databaseSpecific().get("cwe_ids");
                cweIds.stream()
                        .map(String::toLowerCase)
                        .map(cweId -> cweId.replaceFirst("^cwe-", ""))
                        .map(Integer::parseInt)
                        .forEach(cwes::add);
            } catch (ClassCastException e) {
                LOGGER.warn("Unexpected format of cwe_ids: {}", advisory.databaseSpecific().get("cwe_ids"));
            }
        }

        final var vuln = new Vulnerability(
                advisory.id(),
                advisory.aliases(),
                advisory.related(),
                advisory.details(),
                !cwes.isEmpty() ? cwes : null,
                !ratings.isEmpty() ? ratings : null,
                /* references */ null,
                !matchingCriteriaList.isEmpty() ? matchingCriteriaList : null,
                /* createdAt */ null,
                advisory.published(),
                advisory.modified(),
                advisory.withdrawn());

        database.storeVulnerabilities(List.of(vuln));
    }

}

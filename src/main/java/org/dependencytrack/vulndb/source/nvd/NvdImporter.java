package org.dependencytrack.vulndb.source.nvd;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.nvd.Config;
import io.github.jeremylong.openvulnerability.client.nvd.CpeMatch;
import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.LangString;
import io.github.jeremylong.openvulnerability.client.nvd.Node;
import io.github.jeremylong.openvulnerability.client.nvd.Weakness;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersUtils;
import org.dependencytrack.vulndb.api.Database;
import org.dependencytrack.vulndb.api.Importer;
import org.dependencytrack.vulndb.api.MatchingCriteria;
import org.dependencytrack.vulndb.api.Rating;
import org.dependencytrack.vulndb.api.Reference;
import org.dependencytrack.vulndb.api.Source;
import org.dependencytrack.vulndb.api.Vulnerability;
import org.metaeffekt.core.security.cvss.CvssVector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.values.Part;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;

import static java.util.Comparator.comparingInt;

public final class NvdImporter implements Importer {

    private static final Logger LOGGER = LoggerFactory.getLogger(NvdImporter.class);

    private Database database;
    private HttpClient httpClient;
    private ObjectMapper objectMapper;
    private List<Integer> feedYears;

    @Override
    public Source source() {
        return new Source("nvd", "National Vulnerability Database (NVD)", null, "https://nvd.nist.gov/");
    }

    @Override
    public void init(final Database database) {
        this.database = database;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .configure(JsonReadFeature.ALLOW_TRAILING_COMMA.mappedFeature(), true);
        this.feedYears = IntStream.range(2002, LocalDate.now().getYear()).boxed().toList();
    }

    @Override
    public void runImport() throws Exception {
        // https://nvd.nist.gov/developers/terms-of-use
        LOGGER.info("This product uses the NVD API but is not endorsed or certified by the NVD.");

        for (final int year : this.feedYears) {
            LOGGER.info("Downloading feed file for year {}", year);
            final FeedFile feedFile = downloadFeedFile(year);
            if (feedFile == null) {
                LOGGER.info("Download of feed file for year {} not necessary", year);
                continue;
            }

            LOGGER.info("Processing feed file for year {}", year);
            try (final InputStream inputStream = Files.newInputStream(feedFile.path(), StandardOpenOption.DELETE_ON_CLOSE);
                 final BufferedInputStream bufInputStream = new BufferedInputStream(inputStream);
                 final GZIPInputStream gzipInputStream = new GZIPInputStream(bufInputStream);
                 final JsonParser jsonParser = objectMapper.createParser(gzipInputStream)) {
                jsonParser.nextToken(); // Position cursor at first token

                JsonToken currentToken;
                while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
                    final String fieldName = jsonParser.currentName();
                    currentToken = jsonParser.nextToken();
                    if ("vulnerabilities".equals(fieldName)) {
                        if (currentToken == JsonToken.START_ARRAY) {
                            while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
                                final var defCveItem = objectMapper.readValue(jsonParser, DefCveItem.class);
                                final Vulnerability vuln = convert(defCveItem.getCve());

                                // TODO: Batching
                                database.storeVulnerabilities(List.of(vuln));
                            }
                        } else {
                            jsonParser.skipChildren();
                        }
                    } else {
                        jsonParser.skipChildren();
                    }
                }
            }

            database.putSourceMetadata("lastModified-" + year, String.valueOf(feedFile.lastModified().toEpochSecond()));
        }
    }

    private record FeedFile(Path path, int year, OffsetDateTime lastModified) {
    }

    private FeedFile downloadFeedFile(final int year) throws IOException, InterruptedException {
        final var metaRequest = HttpRequest.newBuilder(
                        URI.create("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.meta".formatted(year)))
                .GET()
                .build();
        final HttpResponse<String> metaResponse = httpClient.send(metaRequest, HttpResponse.BodyHandlers.ofString());
        if (metaResponse.statusCode() != 200) {
            throw new IOException("Unexpected response status " + metaResponse.statusCode());
        }

        final OffsetDateTime lastModified = metaResponse.body().lines()
                .filter(line -> line.startsWith("lastModifiedDate:"))
                .map(line -> line.split(":", 2)[1])
                .map(OffsetDateTime::parse)
                .findAny()
                .orElseThrow();

        final Map<String, String> sourceMetadata = database.getSourceMetadata();
        final OffsetDateTime savedLastModified = Optional.ofNullable(sourceMetadata.get("lastModified-" + year))
                .map(Long::parseLong)
                .map(Instant::ofEpochSecond)
                .map(instant -> OffsetDateTime.ofInstant(instant, ZoneOffset.UTC))
                .orElse(null);
        if (savedLastModified != null
            && (savedLastModified.isBefore(lastModified) || savedLastModified.isEqual(lastModified))) {
            return null;
        }

        final Path filePath = Files.createTempFile(null, ".json.gz");

        final var request = HttpRequest.newBuilder(
                        URI.create("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.json.gz".formatted(year)))
                .GET()
                .build();

        final HttpResponse<Path> response = httpClient.send(request, HttpResponse.BodyHandlers.ofFile(filePath));
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Unexpected response status: " + response.statusCode());
        }

        return new FeedFile(filePath, year, lastModified);
    }

    private Vulnerability convert(final CveItem cveItem) {
        final var ratings = new ArrayList<Rating>();
        if (cveItem.getMetrics() != null) {
            if (cveItem.getMetrics().getCvssMetricV2() != null) {
                cveItem.getMetrics().getCvssMetricV2().sort(comparingInt(metric -> metric.getType().ordinal()));

                for (final CvssV2 metric : cveItem.getMetrics().getCvssMetricV2()) {
                    var vectorString = metric.getCvssData().getVectorString();
                    if (!vectorString.startsWith("CVSS:2.0")) {
                        vectorString = "CVSS:2.0:" + vectorString;
                    }
                    final var vector = CvssVector.parseVector(vectorString);
                    if (vector != null) {
                        ratings.add(new Rating(
                                Rating.Method.CVSSv2,
                                Rating.Severity.ofCvss(vector),
                                vector.toString(),
                                vector.getBaseScore()));
                        break;
                    } else {
                        LOGGER.debug("Failed to parse CVSSv2 vector: {}", metric.getCvssData().getVectorString());
                    }
                }
            }

            if (cveItem.getMetrics().getCvssMetricV30() != null) {
                cveItem.getMetrics().getCvssMetricV30().sort(comparingInt(metric -> metric.getType().ordinal()));

                for (final CvssV3 metric : cveItem.getMetrics().getCvssMetricV30()) {
                    final var vector = CvssVector.parseVector(metric.getCvssData().getVectorString());
                    if (vector != null) {
                        ratings.add(new Rating(
                                Rating.Method.CVSSv3,
                                Rating.Severity.ofCvss(vector),
                                vector.toString(),
                                vector.getBaseScore()));
                        break;
                    } else {
                        LOGGER.debug("Failed to parse CVSSv3.0 vector: {}", metric.getCvssData().getVectorString());
                    }
                }
            }

            if (cveItem.getMetrics().getCvssMetricV31() != null) {
                cveItem.getMetrics().getCvssMetricV31().sort(comparingInt(metric -> metric.getType().ordinal()));

                for (final CvssV3 metric : cveItem.getMetrics().getCvssMetricV31()) {
                    final var vector = CvssVector.parseVector(metric.getCvssData().getVectorString());
                    if (vector != null) {
                        ratings.add(new Rating(
                                Rating.Method.CVSSv3_1,
                                Rating.Severity.ofCvss(vector),
                                vector.toString(),
                                vector.getBaseScore()));
                        break;
                    } else {
                        LOGGER.debug("Failed to parse CVSSv3.1 vector: {}", metric.getCvssData().getVectorString());
                    }
                }
            }

            if (cveItem.getMetrics().getCvssMetricV40() != null) {
                cveItem.getMetrics().getCvssMetricV40().sort(comparingInt(metric -> metric.getType().ordinal()));

                for (final CvssV4 metric : cveItem.getMetrics().getCvssMetricV40()) {
                    final var vector = CvssVector.parseVector(metric.getCvssData().getVectorString());
                    if (vector != null) {
                        ratings.add(new Rating(
                                Rating.Method.CVSSv4,
                                Rating.Severity.ofCvss(vector),
                                vector.toString(),
                                vector.getBaseScore()));
                        break;
                    } else {
                        LOGGER.debug("Failed to parse CVSSv4 vector: {}", metric.getCvssData().getVectorString());
                    }
                }
            }
        }

        final var matchingCriteriaList = new ArrayList<MatchingCriteria>();
        if (cveItem.getConfigurations() != null) {
            final List<CpeMatch> cpeMatches = extractCpeMatches(cveItem.getId(), cveItem.getConfigurations());
            matchingCriteriaList.addAll(cpeMatches.stream()
                    .map(NvdImporter::convertCpeMatch)
                    .toList());
        }

        Instant rejectedAt = null;
        if ("rejected".equalsIgnoreCase(cveItem.getVulnStatus())) {
            // There's no timestamp as to *when* it was rejected.
            // Assume zero instant as stable value.
            rejectedAt = Instant.EPOCH;
        }
//        else if (cveItem.getCveTags() != null) {
//            // TODO: Should we track rejected and disputed separately?
//            for (final CveTag cveTag : cveItem.getCveTags()) {
//                if (cveTag.getTags() != null && cveTag.getTags().contains(CveTag.TagType.DISPUTED)) {
//                    rejectedAt = Instant.EPOCH;
//                    break;
//                }
//            }
//        }

        return new Vulnerability(
                cveItem.getId(),
                /* aliases */ null,
                /* related */ null,
                convertDescriptions(cveItem.getDescriptions()),
                convertWeaknesses(cveItem.getWeaknesses()),
                !ratings.isEmpty() ? ratings : null,
                convertReferences(cveItem.getReferences()),
                !matchingCriteriaList.isEmpty() ? matchingCriteriaList : null,
                /* createdAt */ null,
                cveItem.getPublished() != null
                        ? cveItem.getPublished().toInstant()
                        : null,
                cveItem.getLastModified() != null
                        ? cveItem.getLastModified().toInstant()
                        : null,
                rejectedAt);
    }

    private static String convertDescriptions(final List<LangString> descriptions) {
        if (descriptions == null || descriptions.isEmpty()) {
            return null;
        }

        return descriptions.stream()
                .filter(description -> "en".equalsIgnoreCase(description.getLang()))
                .map(LangString::getValue)
                .collect(Collectors.joining("\n\n"));
    }

    private static List<Integer> convertWeaknesses(final List<Weakness> weaknesses) {
        if (weaknesses == null) {
            return null;
        }

        final List<Integer> cweIds = weaknesses.stream()
                .map(Weakness::getDescription)
                .flatMap(Collection::stream)
                .filter(description -> "en".equalsIgnoreCase(description.getLang()))
                .map(LangString::getValue)
                .map(String::toLowerCase)
                .filter(cweId -> cweId.startsWith("cwe-"))
                .map(cweId -> cweId.toLowerCase().replaceFirst("^cwe-", ""))
                .map(Integer::parseInt)
                .distinct()
                .toList();

        return !cweIds.isEmpty() ? cweIds : null;
    }

    private static List<Reference> convertReferences(final List<io.github.jeremylong.openvulnerability.client.nvd.Reference> nvdReferences) {
        if (nvdReferences == null || nvdReferences.isEmpty()) {
            return null;
        }

        return nvdReferences.stream()
                .map(io.github.jeremylong.openvulnerability.client.nvd.Reference::getUrl)
                .map(url -> new Reference(url, null))
                .toList();
    }

    private static MatchingCriteria convertCpeMatch(final CpeMatch cpeMatch) {
        try {
            final Cpe cpe = CpeParser.parse(cpeMatch.getCriteria());

            final Optional<Vers> optionalVers = VersUtils.versFromNvdRange(
                    cpeMatch.getVersionStartExcluding(),
                    cpeMatch.getVersionStartIncluding(),
                    cpeMatch.getVersionEndExcluding(),
                    cpeMatch.getVersionEndIncluding(),
                    cpe.getVersion());

            return new MatchingCriteria(
                    cpe,
                    null,
                    optionalVers.orElse(null),
                    null,
                    null);

        } catch (CpeParsingException e) {
            throw new RuntimeException(e);
        }
    }

    private static List<CpeMatch> extractCpeMatches(final String cveId, final List<Config> cveConfigs) {
        if (cveConfigs == null) {
            return Collections.emptyList();
        }

        final var cpeMatches = new ArrayList<CpeMatch>();
        for (final Config config : cveConfigs) {
            if (config.getNegate() != null && config.getNegate()) {
                // We can't compute negation.
                continue;
            }
            if (config.getNodes() == null || config.getNodes().isEmpty()) {
                continue;
            }

            config.getNodes().stream()
                    // We can't compute negation.
                    .filter(node -> node.getNegate() == null || !node.getNegate())
                    .filter(node -> node.getCpeMatch() != null)
                    .flatMap(node -> extractCpeMatchesFromNode(cveId, node))
                    // We currently have no interest in non-vulnerable versions.
                    .filter(cpeMatch -> cpeMatch.getVulnerable() == null || cpeMatch.getVulnerable())
                    .forEach(cpeMatches::add);
        }

        return cpeMatches;
    }

    private static Stream<CpeMatch> extractCpeMatchesFromNode(final String cveId, final Node node) {
        // Parse all CPEs in this node, and filter out those that cannot be parsed.
        // Because multiple `CpeMatch`es can refer to the same CPE, group them by CPE.
        final Map<Cpe, List<CpeMatch>> cpeMatchesByCpe = node.getCpeMatch().stream()
                .map(cpeMatch -> {
                    try {
                        return Map.entry(CpeParser.parse(cpeMatch.getCriteria()), cpeMatch);
                    } catch (CpeParsingException e) {
                        LOGGER.warn("Failed to parse CPE %s of %s; Skipping".formatted(cpeMatch.getCriteria(), cveId), e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.groupingBy(Map.Entry::getKey, Collectors.mapping(Map.Entry::getValue, Collectors.toList())));

        // CVE configurations may consist of applications and operating systems. In the case of
        // configurations that contain both application and operating system parts, we do not
        // want both types of CPEs to be associated to the vulnerability as it will lead to
        // false positives on the operating system. https://nvd.nist.gov/vuln/detail/CVE-2015-0312
        // is a good example of this as it contains application CPEs describing various versions
        // of Adobe Flash player, but also contains CPEs for all versions of Windows, macOS, and
        // Linux.
        if (node.getOperator() == Node.Operator.AND) {
            // Re-group `CpeMatch`es by CPE part to determine which are against applications,
            // and which against operating systems. When matches are present for both of them,
            // only use the ones for applications.
            final Map<Part, List<CpeMatch>> cpeMatchesByPart = cpeMatchesByCpe.entrySet().stream()
                    .collect(Collectors.groupingBy(
                            entry -> entry.getKey().getPart(),
                            Collectors.flatMapping(entry -> entry.getValue().stream(), Collectors.toList())));
            if (!cpeMatchesByPart.getOrDefault(Part.APPLICATION, Collections.emptyList()).isEmpty()
                && !cpeMatchesByPart.getOrDefault(Part.OPERATING_SYSTEM, Collections.emptyList()).isEmpty()) {
                return cpeMatchesByPart.get(Part.APPLICATION).stream();
            }
        }

        return cpeMatchesByCpe.values().stream()
                .flatMap(Collection::stream);
    }

}

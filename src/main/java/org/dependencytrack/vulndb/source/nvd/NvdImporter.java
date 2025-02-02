package org.dependencytrack.vulndb.source.nvd;

import io.github.jeremylong.openvulnerability.client.nvd.Config;
import io.github.jeremylong.openvulnerability.client.nvd.CpeMatch;
import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.LangString;
import io.github.jeremylong.openvulnerability.client.nvd.Node;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClient;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClientBuilder;
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

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.github.jeremylong.openvulnerability.client.nvd.NvdCveClientBuilder.aNvdCveApi;
import static java.util.Comparator.comparingInt;

public final class NvdImporter implements Importer {

    private static final Logger LOGGER = LoggerFactory.getLogger(NvdImporter.class);

    private Database database;

    @Override
    public Source source() {
        return new Source("NVD", null, "https://nvd.nist.gov/");
    }

    @Override
    public void init(final Database database) {
        this.database = database;
    }

    @Override
    public void runImport() {
        final var advisoriesImported = new AtomicInteger();
        try (final ScheduledExecutorService statusExecutor = Executors.newSingleThreadScheduledExecutor();
             final var apiClient = createApiClient()) {
            statusExecutor.scheduleAtFixedRate(
                    () -> LOGGER.info("Mirrored {}/{}", advisoriesImported, apiClient.getTotalAvailable()),
                    1, 3, TimeUnit.SECONDS);

            while (apiClient.hasNext()) {
                final Collection<DefCveItem> defCveItems = apiClient.next();
                final List<Vulnerability> vulns = defCveItems.stream()
                        .map(DefCveItem::getCve)
                        .map(this::convert)
                        .toList();

                database.storeVulnerabilities(vulns);
                advisoriesImported.addAndGet(vulns.size());
            }

            // Unfortunately batches of CVEs are arriving out-of-order so we can only
            // save the latest last modified timestamp at the very end.
            database.putSourceMetadata(
                    "last_modified_epoch_seconds",
                    String.valueOf(apiClient.getLastUpdated().toInstant().getEpochSecond()));
        }
    }

    private NvdCveClient createApiClient() {
        final NvdCveClientBuilder clientBuilder = aNvdCveApi();

        Optional.ofNullable(database.getSourceMetadata().get("last_modified_epoch_seconds"))
                .map(Long::parseLong)
                .map(Instant::ofEpochSecond)
                .map(instant -> ZonedDateTime.ofInstant(instant, ZoneOffset.UTC))
                .ifPresent(lastModified -> clientBuilder.withLastModifiedFilter(
                        lastModified,
                        lastModified.plusDays(120)));

        return clientBuilder.build();
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

        return new Vulnerability(
                cveItem.getId(),
                null,
                convertDescriptions(cveItem.getDescriptions()),
                convertWeaknesses(cveItem.getWeaknesses()),
                !ratings.isEmpty() ? ratings : null,
                convertReferences(cveItem.getReferences()),
                !matchingCriteriaList.isEmpty() ? matchingCriteriaList : null,
                null,
                cveItem.getPublished() != null
                        ? cveItem.getPublished().toInstant()
                        : null,
                cveItem.getLastModified() != null
                        ? cveItem.getLastModified().toInstant()
                        : null,
                null);
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

        return weaknesses.stream()
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

package org.dependencytrack.vulndb.source.github;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import io.github.jeremylong.openvulnerability.client.ghsa.CVSS;
import io.github.jeremylong.openvulnerability.client.ghsa.CWE;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClient;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder;
import io.github.jeremylong.openvulnerability.client.ghsa.Identifier;
import io.github.jeremylong.openvulnerability.client.ghsa.Package;
import io.github.jeremylong.openvulnerability.client.ghsa.SecurityAdvisory;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersUtils;
import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
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
import org.slf4j.MDC;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.github.packageurl.PackageURLBuilder.aPackageURL;
import static io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder.aGitHubSecurityAdvisoryClient;

public final class GitHubImporter implements Importer {

    private static final Logger LOGGER = LoggerFactory.getLogger(GitHubImporter.class);

    private Database database;

    @Override
    public Source source() {
        return new Source("github", "GitHub Advisory Database", "CC-BY-4.0", "https://github.com/advisories");
    }

    @Override
    public void init(final Database database) {
        this.database = database;
    }

    @Override
    public void runImport() {
        final var vulnsImported = new AtomicInteger();
        try (final ScheduledExecutorService statusExecutor = Executors.newSingleThreadScheduledExecutor();
             final GitHubSecurityAdvisoryClient apiClient = createApiClient()) {
            statusExecutor.scheduleAtFixedRate(
                    () -> LOGGER.info("Imported {}/{} vulnerabilities", vulnsImported, apiClient.getTotalAvailable()),
                    1, 3, TimeUnit.SECONDS);

            while (apiClient.hasNext()) {
                final Collection<SecurityAdvisory> advisories = apiClient.next();
                final List<Vulnerability> vulns = advisories.stream()
                        .map(advisory -> {
                            try (var ignored = MDC.putCloseable("vulnId", advisory.getGhsaId())) {
                                return convert(advisory);
                            }
                        })
                        .toList();
                if (vulns.isEmpty()) {
                    break;
                }

                database.storeVulnerabilities(vulns);
                database.putSourceMetadata(
                        "last_modified_epoch_seconds",
                        String.valueOf(apiClient.getLastUpdated().toInstant().getEpochSecond()));
                vulnsImported.addAndGet(vulns.size());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private GitHubSecurityAdvisoryClient createApiClient() {
        final HttpAsyncClientBuilder httpClientBuilder = HttpAsyncClients.custom()
                .setRetryStrategy(new GitHubHttpRequestRetryStrategy())
                .useSystemProperties();

        final GitHubSecurityAdvisoryClientBuilder clientBuilder = aGitHubSecurityAdvisoryClient()
                .withHttpClientSupplier(httpClientBuilder::build)
                .withApiKey(System.getenv("GITHUB_TOKEN"));

        Optional.ofNullable(database.getSourceMetadata().get("last_modified_epoch_seconds"))
                .map(Long::parseLong)
                .map(Instant::ofEpochSecond)
                .map(instant -> ZonedDateTime.ofInstant(instant, ZoneOffset.UTC))
                .ifPresent(clientBuilder::withUpdatedSinceFilter);

        return clientBuilder.build();
    }

    private Vulnerability convert(final SecurityAdvisory advisory) {
        final var aliases = new ArrayList<String>();
        if (advisory.getIdentifiers() != null) {
            for (final Identifier identifier : advisory.getIdentifiers()) {
                if ("cve".equalsIgnoreCase(identifier.getType())) {
                    aliases.add(identifier.getValue());
                }
            }
        }

        final var cwes = new ArrayList<Integer>();
        if (advisory.getCwes() != null && advisory.getCwes().getEdges() != null) {
            for (final CWE cwe : advisory.getCwes().getEdges()) {
                final String cweId = cwe.getCweId().toLowerCase().replaceFirst("^cwe-", "");
                cwes.add(Integer.parseInt(cweId));
            }
        }

        final var ratings = new ArrayList<Rating>();
        if (advisory.getCvssSeverities() != null) {
            if (advisory.getCvssSeverities().getCvssV3() != null
                && advisory.getCvssSeverities().getCvssV3().getVectorString() != null) {
                final CVSS cvss = advisory.getCvssSeverities().getCvssV3();

                final var vector = CvssVector.parseVector(cvss.getVectorString());
                if (vector != null) {
                    ratings.add(new Rating(
                            Rating.Method.CVSSv3,
                            Rating.Severity.ofCvss(vector),
                            advisory.getCvssSeverities().getCvssV3().getVectorString(),
                            advisory.getCvssSeverities().getCvssV3().getScore()));
                } else {
                    LOGGER.warn("Failed to parse CVSSv3 vector {}", cvss.getVectorString());
                    ratings.add(new Rating(
                            Rating.Method.CVSSv3,
                            Rating.Severity.UNKNOWN,
                            cvss.getVectorString(),
                            cvss.getScore()));
                }
            }

            if (advisory.getCvssSeverities().getCvssV4() != null
                && advisory.getCvssSeverities().getCvssV4().getVectorString() != null) {
                final CVSS cvss = advisory.getCvssSeverities().getCvssV4();

                final var vector = CvssVector.parseVector(cvss.getVectorString());
                if (vector != null) {
                    ratings.add(new Rating(
                            Rating.Method.CVSSv4,
                            Rating.Severity.ofCvss(vector),
                            vector.toString(),
                            vector.getOverallScore()));
                } else {
                    LOGGER.warn("Failed to parse CVSSv4 vector {}", cvss.getVectorString());
                    ratings.add(new Rating(
                            Rating.Method.CVSSv4,
                            Rating.Severity.UNKNOWN,
                            cvss.getVectorString(),
                            cvss.getScore()));
                }
            }
        }

        final var references = new ArrayList<Reference>();
        if (advisory.getReferences() != null) {
            for (final io.github.jeremylong.openvulnerability.client.ghsa.Reference reference : advisory.getReferences()) {
                references.add(new Reference(reference.getUrl(), null));
            }
        }

        final var matchingCriteriaList = new ArrayList<MatchingCriteria>();
        if (advisory.getVulnerabilities() != null && advisory.getVulnerabilities().getEdges() != null) {
            for (final io.github.jeremylong.openvulnerability.client.ghsa.Vulnerability ghsaVuln : advisory.getVulnerabilities().getEdges()) {
                final PackageURL purl = convertToPurl(ghsaVuln.getPackage());
                if (purl == null) {
                    continue;
                }

                final Vers vers;
                try {
                    vers = VersUtils.versFromGhsaRange(
                            ghsaVuln.getPackage().getEcosystem(),
                            ghsaVuln.getVulnerableVersionRange());
                } catch (RuntimeException e) {
                    LOGGER.warn("Failed to build vers from GHSA range {}", ghsaVuln.getVulnerableVersionRange(), e);
                    continue;
                }

                matchingCriteriaList.add(new MatchingCriteria(
                        null,
                        purl,
                        vers,
                        null,
                        null));
            }
        }

        return new Vulnerability(
                advisory.getGhsaId(),
                !aliases.isEmpty() ? aliases : null,
                /* related */ null,
                advisory.getDescription(),
                !cwes.isEmpty() ? cwes : null,
                !ratings.isEmpty() ? ratings : null,
                !references.isEmpty() ? references : null,
                !matchingCriteriaList.isEmpty() ? matchingCriteriaList : null,
                /* createdAt */ null,
                advisory.getPublishedAt() != null
                        ? advisory.getPublishedAt().toInstant()
                        : null,
                advisory.getUpdatedAt() != null
                        ? advisory.getPublishedAt().toInstant()
                        : null,
                advisory.getWithdrawnAt() != null
                        ? advisory.getWithdrawnAt().toInstant()
                        : null);
    }

    private PackageURL convertToPurl(final Package pkg) {
        final String purlType = switch (pkg.getEcosystem().toLowerCase()) {
            case "composer" -> PackageURL.StandardTypes.COMPOSER;
            case "erlang" -> PackageURL.StandardTypes.HEX;
            case "go" -> PackageURL.StandardTypes.GOLANG;
            case "maven" -> PackageURL.StandardTypes.MAVEN;
            case "npm" -> PackageURL.StandardTypes.NPM;
            case "nuget" -> PackageURL.StandardTypes.NUGET;
            case "other" -> PackageURL.StandardTypes.GENERIC;
            case "pip" -> PackageURL.StandardTypes.PYPI;
            case "pub" -> "pub"; // https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#pub
            case "rubygems" -> PackageURL.StandardTypes.GEM;
            case "rust" -> PackageURL.StandardTypes.CARGO;
            case "swift" -> "swift"; // https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#swift
            default -> {
                // Not optimal, but still better than ignoring the package entirely.
                LOGGER.warn("Unrecognized ecosystem {}; Assuming PURL type {} for {}",
                        pkg.getEcosystem(), PackageURL.StandardTypes.GENERIC, pkg);
                yield PackageURL.StandardTypes.GENERIC;
            }
        };

        final PackageURLBuilder purlBuilder = aPackageURL().withType(purlType);
        if (PackageURL.StandardTypes.MAVEN.equals(purlType) && pkg.getName().contains(":")) {
            final String[] nameParts = pkg.getName().split(":", 2);
            purlBuilder
                    .withNamespace(nameParts[0])
                    .withName(nameParts[1]);
        } else if ((PackageURL.StandardTypes.COMPOSER.equals(purlType)
                    || PackageURL.StandardTypes.GOLANG.equals(purlType)
                    || PackageURL.StandardTypes.NPM.equals(purlType)
                    || PackageURL.StandardTypes.GENERIC.equals(purlType))
                   && pkg.getName().contains("/")) {
            final String[] nameParts = pkg.getName().split("/");
            final String namespace = String.join("/", Arrays.copyOfRange(nameParts, 0, nameParts.length - 1));
            purlBuilder
                    .withNamespace(namespace)
                    .withName(nameParts[nameParts.length - 1]);
        } else {
            purlBuilder.withName(pkg.getName());
        }

        try {
            return purlBuilder.build();
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Failed to assemble a valid PURL from {}", pkg, e);
            return null;
        }
    }

}

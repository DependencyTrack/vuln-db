package org.dependencytrack.vulndb.cli;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.Vers;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.parsers.BomParserFactory;
import org.dependencytrack.vulndb.store.MatchingCriteriaRecord;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.sqlite3.SQLitePlugin;
import picocli.CommandLine.Command;
import picocli.CommandLine.Help.Ansi;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.values.Part;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Callable;

@Command(name = "scan", description = "Test a database by scanning BOMs.")
public class ScanCommand implements Callable<Integer> {

    @Option(names = {"-d", "--database"})
    Path databaseFilePath;

    @Option(names = {"-i", "--ensure-indexes"})
    boolean ensureIndexes;

    @Parameters
    Path bomFilePath;

    @Override
    public Integer call() throws Exception {
        final Jdbi jdbi = Jdbi
                .create("jdbc:sqlite:%s".formatted(databaseFilePath))
                .installPlugin(new SQLitePlugin());

        maybeCreateIndexes(jdbi);

        final byte[] bomBytes = Files.readAllBytes(bomFilePath);
        final Bom bom = BomParserFactory.createParser(bomBytes).parse(bomBytes);

        final var matchesByComponentByVulnId = new TreeMap<String, Map<Component, Set<MatchMetadata>>>();

        try (final Handle handle = jdbi.open()) {
            // TODO: Consider metadata.component, nested components etc.

            for (final Component component : bom.getComponents()) {
                final Set<MatchMetadata> matches = scan(handle, component);
                if (matches.isEmpty()) {
                    continue;
                }

                for (final MatchMetadata match : matches) {
                    final Map<Component, Set<MatchMetadata>> matchesByComponent =
                            matchesByComponentByVulnId.computeIfAbsent(
                                    match.vulnId(), ignored -> new TreeMap<>(
                                            Comparator.comparing(Component::getName)
                                                    .thenComparing(Component::getVersion)));

                    matchesByComponent.computeIfAbsent(
                            component, ignored -> new HashSet<>()).add(match);
                }
            }
        }

        if (matchesByComponentByVulnId.isEmpty()) {
            System.out.println("@|bold,green no vulnerabilities identified|@");
            return 0;
        }

        for (final String vulnId : matchesByComponentByVulnId.keySet()) {
            final Map<Component, Set<MatchMetadata>> matchesByComponent = matchesByComponentByVulnId.get(vulnId);

            System.out.println(Ansi.AUTO.string("@|bold,red,underline %s|@".formatted(vulnId)));

            for (final Map.Entry<Component, Set<MatchMetadata>> entry : matchesByComponent.entrySet()) {
                final Component component = entry.getKey();
                final Set<MatchMetadata> matches = entry.getValue();

                String componentName = component.getName();
                if (component.getGroup() != null) {
                    componentName = component.getGroup() + "/" + componentName;
                }
                if (component.getVersion() != null) {
                    componentName = componentName + "@" + component.getVersion();
                }

                System.out.println("- " + componentName);

                for (final MatchMetadata match : matches) {
                    System.out.println(Ansi.AUTO.string("  + matched: @|italic %s|@ (source: %s)".formatted(
                            match.criteriaVers(), match.criteriaSource())));
                }

                System.out.println();
            }
        }

        // TODO: Resolve vulnIds to vuln_data records and present that data
        //  in a visually pleasing way. Offer some consistently formatted,
        //  machine-readable output to enable diffing.

        return 0;
    }

    private void maybeCreateIndexes(final Jdbi jdbi) {
        if (!ensureIndexes) {
            return;
        }

        jdbi.useHandle(handle -> {
            handle.execute("""
                    create index if not exists matching_criteria_purl_ns_idx
                        on matching_criteria(purl_type, purl_namespace, purl_name)
                     where purl_namespace is not null;
                    """);

            handle.execute("""
                    create index if not exists matching_criteria_purl_idx
                        on matching_criteria(purl_type, purl_name)
                     where purl_namespace is null;
                    """);
        });
    }

    private record MatchMetadata(
            String vulnId,
            String criteriaSource,
            String criteriaVers) {
    }

    private Set<MatchMetadata> scan(
            final Handle handle,
            final Component component) throws MalformedPackageURLException, CpeParsingException {
        final var affectedVulnIds = new HashSet<MatchMetadata>();

        if (component.getCpe() != null) {
            final var cpe = CpeParser.parse(component.getCpe());

            final List<MatchingCriteriaRecord> criteriaRecords = getCriteriaByCpe(handle, cpe);
            for (final MatchingCriteriaRecord criteriaRecord : criteriaRecords) {
                // TODO
            }
        }

        if (component.getPurl() != null) {
            final var purl = new PackageURL(component.getPurl());

            final List<MatchingCriteriaRecord> criteriaRecords = getCriteriaByPurl(handle, purl);
            for (final MatchingCriteriaRecord criteriaRecord : criteriaRecords) {
                if (criteriaRecord.versions() == null) {
                    continue;
                }

                final Vers vers = Vers.parse(criteriaRecord.versions());
                if (vers.contains(purl.getVersion())) {
                    // Handle cases where a Debian vulnerability only apply to specific
                    // releases of Debian. Note that this requires both the criteria, as well
                    // as the package to declare a Debian release version.
                    // It can't be reliably deduced from package versions or vers ranges alone.
                    // TODO: For the love of god make this less atrocious.
                    if (purl.getType().equals(PackageURL.StandardTypes.DEBIAN)
                        && purl.getQualifiers() != null
                        && purl.getQualifiers().containsKey("distro")
                        && purl.getQualifiers().get("distro").startsWith("debian-")
                        && "debian-version".equals(criteriaRecord.additionalCriteriaType())) {
                        final String distroVersion = purl.getQualifiers().get("distro").replaceFirst("^debian-", "");
                        if (!distroVersion.startsWith(new String(criteriaRecord.additionalCriteria()))) {
                            System.out.println(
                                    "Discarding range %s due to Debian version mismatch (package=%s, criteria=%s)".formatted(
                                            criteriaRecord.versions(), distroVersion, new String(criteriaRecord.additionalCriteria())));
                            continue;
                        }
                    }

                    // TODO: Check more additional criteria types.

                    affectedVulnIds.add(new MatchMetadata(
                            criteriaRecord.vulnId(),
                            criteriaRecord.sourceName(),
                            criteriaRecord.versions()));
                }
            }
        }

        return affectedVulnIds;
    }

    private List<MatchingCriteriaRecord> getCriteriaByCpe(final Handle handle, final Cpe cpe) {
        final var params = new HashMap<String, Object>();
        final var filterParts = new ArrayList<String>();

        // The query composition below represents a partial implementation of the CPE
        // matching logic. It makes references to table 6-2 of the CPE name matching
        // specification: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
        //
        // In CPE matching terms, the parameters of this method represent the target,
        // and the `VulnerableSoftware`s in the database represent the source.
        //
        // While the source *can* contain wildcards ("*", "?"), there is currently (Oct. 2023)
        // no occurrence of part, vendor, or product with wildcards in the NVD database.
        // Evaluating wildcards in the source can only be done in-memory. If we wanted to do that,
        // we'd have to fetch *all* records, which is not practical.

        if (cpe.getPart() != Part.ANY && cpe.getPart() != Part.NA) {
            // | No. | Source A-V      | Target A-V | Relation             |
            // | :-- | :-------------- | :--------- | :------------------- |
            // | 3   | ANY             | i          | SUPERSET             |
            // | 7   | NA              | i          | DISJOINT             |
            // | 9   | i               | i          | EQUAL                |
            // | 10  | i               | k          | DISJOINT             |
            // | 14  | m1 + wild cards | m2         | SUPERSET or DISJOINT |
            filterParts.add("(cpe_part = '*' or cpe_part = :cpePart)");
            params.put("cpePart", cpe.getPart().getAbbreviation().toLowerCase());

            // NOTE: Target *could* include wildcard, but the relation
            // for those cases is undefined:
            //
            // | No. | Source A-V      | Target A-V      | Relation   |
            // | :-- | :-------------- | :-------------- | :--------- |
            // | 4   | ANY             | m + wild cards  | undefined  |
            // | 8   | NA              | m + wild cards  | undefined  |
            // | 11  | i               | m + wild cards  | undefined  |
            // | 17  | m1 + wild cards | m2 + wild cards | undefined  |
        } else if (cpe.getPart() == Part.NA) {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 2   | ANY            | NA         | SUPERSET |
            // | 6   | NA             | NA         | EQUAL    |
            // | 12  | i              | NA         | DISJOINT |
            // | 16  | m + wild cards | NA         | DISJOINT |
            filterParts.add("(cpe_part = '*' or cpe_part = '-')");
        } else {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 1   | ANY            | ANY        | EQUAL    |
            // | 5   | NA             | ANY        | SUBSET   |
            // | 13  | i              | ANY        | SUBSET   |
            // | 15  | m + wild cards | ANY        | SUBSET   |
            filterParts.add("cpe_part is not null");
        }

        if (!"*".equals(cpe.getVendor()) && !"-".equals(cpe.getVendor())) {
            filterParts.add("(cpe_vendor = '*' or cpe_vendor = :cpeVendor)");
            params.put("cpeVendor", cpe.getVendor().toLowerCase());
        } else if ("-".equals(cpe.getVendor())) {
            filterParts.add("(cpe_vendor = '*' or cpe_vendor = '-')");
        } else {
            filterParts.add("cpe_vendor is not null");
        }

        if (!"*".equals(cpe.getProduct()) && !"-".equals(cpe.getProduct())) {
            filterParts.add("(cpe_product = '*' or cpe_product = :cpeProduct)");
            params.put("cpeProduct", cpe.getProduct().toLowerCase());
        } else if ("-".equals(cpe.getProduct())) {
            filterParts.add("(cpe_product = '*' or cpe_product = '-')");
        } else {
            filterParts.add("cpe_product is not null");
        }

        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from main.matching_criteria
                 where %s
                """.formatted(String.join(" and ", filterParts)));

        return query
                .bindMap(params)
                .map(ConstructorMapper.of(MatchingCriteriaRecord.class))
                .list();
    }

    private List<MatchingCriteriaRecord> getCriteriaByPurl(final Handle handle, final PackageURL purl) {
        final Query query = handle.createQuery("""
                select *
                  from matching_criteria
                 where purl_type = :purlType
                   and ((:purlNamespace is null and purl_namespace is null)
                        or (purl_namespace = :purlNamespace))
                   and purl_name = :purlName
                """);

        return query
                .bind("purlType", purl.getType())
                .bind("purlNamespace", purl.getNamespace())
                .bind("purlName", purl.getName())
                .map(ConstructorMapper.of(MatchingCriteriaRecord.class))
                .list();
    }

}

package org.dependencytrack.vulndb;

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.sqlite3.SQLitePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;

@Command(name = "merge", description = "Merge multiple databases into one.")
public class MergeCommand implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(MergeCommand.class);

    @Option(names = {"-o", "--output"}, defaultValue = "all.sqlite")
    private Path outputFilePath;

    @Parameters
    private List<Path> inputFilePaths;

    @Override
    public void run() {
        final Jdbi jdbi = Jdbi
                .create("jdbc:sqlite:%s".formatted(outputFilePath))
                .installPlugin(new SQLitePlugin());
        jdbi.useHandle(MergeCommand::createSchema);

        for (final Path inputFilePath : inputFilePaths) {
            try (final Handle handle = jdbi.open();
                 var ignoredMdcInputFile = MDC.putCloseable("inputFile", inputFilePath.toString())) {
                handle.execute("attach database ? as other", inputFilePath);

                LOGGER.info("Merging source tables");
                handle.execute("""
                        insert into main.source(name, display_name, license, url)
                        select *
                          from other.source
                         where 1 = 1
                        on conflict(name) do update
                        set display_name = excluded.display_name
                          , license = excluded.license
                          , url = excluded.url
                        """);

                LOGGER.info("Merging source_metadata tables");
                handle.execute("""
                        insert into main.source_metadata(source_name, key, value, created_at, updated_at)
                        select * from other.source_metadata
                         where 1 = 1
                        on conflict(source_name, key) do update
                        set value = excluded.value
                          , created_at = excluded.created_at
                          , updated_at = excluded.updated_at
                        where excluded.created_at > main.source_metadata.created_at
                           or excluded.updated_at > main.source_metadata.updated_at
                        """);

                LOGGER.info("Merging vuln tables");
                handle.execute("""
                        insert into main.vuln(id)
                        select * 
                          from other.vuln
                         where 1 = 1
                        on conflict(id) do nothing
                        """);

                LOGGER.info("Merging vuln_alias tables");
                handle.execute("""
                        insert into main.vuln_alias(
                          source_name
                        , vuln_id
                        , alias_id
                        , created_at
                        , deleted_at
                        )
                        select * 
                          from other.vuln_alias
                         where 1 = 1
                        on conflict(source_name, vuln_id, alias_id) do update
                        set created_at = excluded.created_at
                          , deleted_at = excluded.deleted_at
                        where excluded.created_at > main.vuln_alias.created_at
                           or excluded.deleted_at is distinct from main.vuln_alias.deleted_at 
                        """);

                LOGGER.info("Merging vuln_data tables");
                handle.execute("""
                        insert into main.vuln_data(
                          source_name
                        , vuln_id
                        , description
                        , cwes
                        , source_created_at
                        , source_published_at
                        , source_updated_at
                        , source_rejected_at
                        , created_at
                        , updated_at
                        )
                        select *
                          from other.vuln_data
                         where 1 = 1
                        on conflict(source_name, vuln_id) do update
                        set description = excluded.description
                          , cwes = excluded.cwes
                          , source_created_at = excluded.source_created_at
                          , source_published_at = excluded.source_published_at
                          , source_updated_at = excluded.source_updated_at
                          , source_rejected_at = excluded.source_rejected_at
                          , created_at = excluded.created_at
                          , updated_at = excluded.updated_at
                        where excluded.created_at > main.vuln_data.created_at
                           or excluded.updated_at > main.vuln_data.updated_at
                        """);

                LOGGER.info("Merging vuln_rating tables");
                handle.execute("""
                        insert into main.vuln_rating(
                          source_name
                        , vuln_id
                        , method
                        , severity
                        , vector
                        , score
                        , created_at
                        , updated_at
                        )
                        select * 
                          from other.vuln_rating
                         where 1 = 1
                        on conflict(source_name, vuln_id, method) do update
                        set severity = excluded.severity
                          , vector = excluded.vector
                          , score = excluded.score
                          , created_at = excluded.created_at
                          , updated_at = excluded.updated_at
                        where excluded.created_at > main.vuln_rating.created_at
                           or excluded.updated_at > main.vuln_rating.updated_at
                        """);

                LOGGER.info("Merging vuln_reference tables");
                handle.execute("""
                        insert into main.vuln_reference(source_name, vuln_id, url, name)
                        select * 
                          from other.vuln_reference
                         where 1 = 1
                        on conflict(source_name, vuln_id, url) do nothing
                        """);

                LOGGER.info("Merging matching_criteria tables");
                handle.execute("""
                        insert into main.matching_criteria(
                          source_name
                        , vuln_id
                        , cpe
                        , cpe_part
                        , cpe_vendor
                        , cpe_product
                        , purl_type
                        , purl_namespace
                        , purl_name
                        , versions
                        , additional_criteria_type
                        , additional_criteria
                        , created_at
                        )
                        select source_name
                             , vuln_id
                             , cpe
                             , cpe_part
                             , cpe_vendor
                             , cpe_product
                             , purl_type
                             , purl_namespace
                             , purl_name
                             , versions
                             , additional_criteria_type
                             , additional_criteria
                             , created_at
                          from other.matching_criteria
                        """);

                LOGGER.info("Merging completed");
            }
        }

        // Force a vacuum to ensure the final database is stored as efficiently as possible.
        LOGGER.info("Vacuuming result database");
        jdbi.useHandle(handle -> handle.execute("VACUUM"));
    }

    private static void createSchema(final Handle handle) {
        final byte[] schemaBytes;
        try (final InputStream inputStream = MergeCommand.class.getClassLoader().getResourceAsStream("schema.sql")) {
            if (inputStream == null) {
                throw new IllegalStateException("Schema file not found");
            }

            schemaBytes = inputStream.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read schema file", e);
        }

        for (final String sqlStatement : new String(schemaBytes).split(";")) {
            handle.execute(sqlStatement);
        }
    }

}

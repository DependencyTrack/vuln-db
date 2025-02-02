package org.dependencytrack.vulndb;

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.sqlite3.SQLitePlugin;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

@Command(name = "merge")
public class MergeCommand implements Runnable {

    @Option(names = "-output", defaultValue = "merged.sqlite")
    private String outputFilePath;

    @Parameters
    private List<String> inputFilePaths;

    @Override
    public void run() {
        final Jdbi jdbi = Jdbi
                .create("jdbc:sqlite:%s".formatted(outputFilePath))
                .installPlugin(new SQLitePlugin());
        jdbi.useHandle(MergeCommand::createSchema);

        for (final String inputFilePath : inputFilePaths) {
            try (final Handle handle = jdbi.open()) {
                handle.execute("attach database ? as other", inputFilePath);

                handle.execute("""
                        insert into main.source(name, license, url)
                        select *
                          from other.source
                         where 1 = 1
                        on conflict(name) do nothing
                        """);
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
                handle.execute("""
                        insert into main.vuln(id)
                        select * 
                          from other.vuln
                         where 1 = 1
                        on conflict(id) do nothing
                        """);
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
                handle.execute("""
                        insert into main.vuln_reference(source_name, vuln_id, url, name)
                        select * 
                          from other.vuln_reference
                         where 1 = 1
                        on conflict(source_name, vuln_id, url) do nothing
                        """);
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
                        , updated_at
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
                             , updated_at
                          from other.matching_criteria
                        """);
            }
        }

        // Force a vacuum to ensure the final database is stored as efficiently as possible.
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

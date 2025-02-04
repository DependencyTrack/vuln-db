package org.dependencytrack.vulndb.store;

import org.dependencytrack.vulndb.api.Database;
import org.dependencytrack.vulndb.api.MatchingCriteria;
import org.dependencytrack.vulndb.api.Rating;
import org.dependencytrack.vulndb.api.Reference;
import org.dependencytrack.vulndb.api.Source;
import org.dependencytrack.vulndb.api.Vulnerability;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.jackson2.Jackson2Plugin;
import org.jdbi.v3.sqlite3.SQLitePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.function.Predicate.not;

public final class DatabaseImpl implements Database, Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseImpl.class);

    private final Jdbi jdbi;
    private final Source source;

    private DatabaseImpl(final Jdbi jdbi, final Source source) {
        this.jdbi = jdbi;
        this.source = source;
    }

    public static DatabaseImpl forSource(final Path workspacePath, final Source source) {
        final Path databaseFilePath = workspacePath.resolve("%s.sqlite".formatted(source.name()));

        final var jdbi = Jdbi
                .create("jdbc:sqlite:" + databaseFilePath)
                .installPlugin(new Jackson2Plugin())
                .installPlugin(new SQLitePlugin());

        final var database = new DatabaseImpl(jdbi, source);
        database.createSchema();
        database.ensureSourceExists(source);

        return database;
    }

    @Override
    public void close() {

    }

    private void createSchema() {
        final byte[] schemaBytes;
        try (final InputStream inputStream = getClass().getClassLoader().getResourceAsStream("schema.sql")) {
            if (inputStream == null) {
                throw new IllegalStateException("Schema file not found");
            }

            schemaBytes = inputStream.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read schema file", e);
        }

        jdbi.useHandle(handle -> {
            for (final String sqlStatement : new String(schemaBytes).split(";")) {
                handle.execute(sqlStatement);
            }
        });
    }

    private void ensureSourceExists(final Source source) {
        jdbi.useTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    insert into source(name, display_name, license, url)
                    values (:name, :displayName, :license, :url)
                    on conflict (name) do update
                    set display_name = excluded.display_name
                      , license = excluded.license
                      , url = excluded.url
                    """);

            update.bindMethods(source).execute();
        });
    }

    @Override
    public Map<String, String> getSourceMetadata() {
        return jdbi.withHandle(handle -> {
            final Query query = handle.createQuery("""
                    select *
                      from source_metadata
                     where source_name = :name
                    """);

            return query
                    .bindMethods(source)
                    .map(ConstructorMapper.of(SourceMetadataRecord.class))
                    .stream()
                    .collect(Collectors.toMap(
                            SourceMetadataRecord::key,
                            SourceMetadataRecord::value));
        });
    }

    @Override
    public void putSourceMetadata(final String key, final String value) {
        jdbi.useHandle(handle -> {
            final Update update = handle.createUpdate("""
                    insert into source_metadata(
                      source_name
                    , key
                    , value
                    ) values(
                      :source.name
                    , :key
                    , :value
                    )
                    on conflict (source_name, key) do update
                    set value = :value
                      , updated_at = unixepoch()
                    where excluded.value != source_metadata.value
                    """);

            update
                    .bindMethods("source", source)
                    .bind("key", key)
                    .bind("value", value)
                    .execute();
        });
    }

    @Override
    public void storeVulnerabilities(final Collection<Vulnerability> vulns) {
        final var vulnIds = new HashSet<String>();
        final var aliasesByVulnId = new HashMap<String, List<String>>();
        final var dataRecordByVulnId = new HashMap<String, VulnerabilityDataRecord>(vulns.size());
        final var ratingRecordByIdentity = new HashMap<RatingIdentity, VulnerabilityRatingRecord>(vulns.size());
        final var referenceRecordByIdentity = new HashMap<ReferenceIdentity, VulnerabilityReferenceRecord>(vulns.size());
        final var matchingCriteriaRecordByIdentity = new HashMap<MatchingCriteriaIdentity, MatchingCriteriaRecord>();

        for (final Vulnerability vuln : vulns) {
            vulnIds.add(vuln.id());

            if (vuln.aliases() != null) {
                aliasesByVulnId.put(vuln.id(), vuln.aliases());
            }

            dataRecordByVulnId.put(vuln.id(), VulnerabilityDataRecord.of(source, vuln));

            if (vuln.ratings() != null) {
                for (final Rating rating : vuln.ratings()) {
                    ratingRecordByIdentity.put(
                            new RatingIdentity(vuln.id(), rating.method().name().replace("_", ".")),
                            VulnerabilityRatingRecord.of(source, vuln.id(), rating));
                }
            }

            if (vuln.references() != null) {
                for (final Reference reference : vuln.references()) {
                    referenceRecordByIdentity.put(
                            new ReferenceIdentity(vuln.id(), reference.url()),
                            VulnerabilityReferenceRecord.of(source, vuln.id(), reference));
                }
            }

            if (vuln.matchingCriteria() != null) {
                for (final MatchingCriteria matchingCriteria : vuln.matchingCriteria()) {
                    final var record = MatchingCriteriaRecord.of(source, vuln.id(), matchingCriteria);
                    matchingCriteriaRecordByIdentity.put(MatchingCriteriaIdentity.of(record), record);
                }
            }
        }

        jdbi.useTransaction(handle -> {
            final Map<String, List<String>> existingAliasesByVulnId =
                    getAliases(handle, vulnIds);
            final Map<String, VulnerabilityDataRecord> existingDataRecordByVulnId =
                    getDataRecords(handle, vulnIds);
            final Map<RatingIdentity, VulnerabilityRatingRecord> existingRatingRecordByIdentity =
                    getRatingRecords(handle, vulnIds);
            final Map<ReferenceIdentity, VulnerabilityReferenceRecord> existingReferenceRecordByIdentity =
                    getReferenceRecords(handle, vulnIds);
            final Map<MatchingCriteriaIdentity, MatchingCriteriaRecord> existingMatchingCriteriaRecordByIdentity =
                    getMatchingCriteriaRecords(handle, vulnIds);

            for (final String vulnId : vulnIds) {
                maybeCreateVulnerability(handle, vulnId);

                final List<String> aliases = aliasesByVulnId.getOrDefault(vulnId, Collections.emptyList());
                final List<String> existingAliases = existingAliasesByVulnId.getOrDefault(vulnId, Collections.emptyList());
                final List<String> aliasesToCreate = aliases.stream()
                        .filter(not(existingAliases::contains))
                        .toList();
                final List<String> aliasesToDelete = aliases.stream()
                        .filter(not(aliases::contains))
                        .toList();
                for (final String aliasId : aliasesToCreate) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("{}: creating alias {}", vulnId, aliasId);
                    }
                    createAlias(handle, vulnId, aliasId);
                }
                for (final String aliasId : aliasesToDelete) {
                    LOGGER.info("{}: deleting alias {} because it is no longer reported", vulnId, aliasId);
                    deleteAlias(handle, vulnId, aliasId);
                }

                final VulnerabilityDataRecord dataRecord = dataRecordByVulnId.get(vulnId);
                final VulnerabilityDataRecord existingDataRecord = existingDataRecordByVulnId.get(vulnId);
                if (existingDataRecord == null) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("{}: creating data {}", vulnId, dataRecord);
                    }
                    createDataRecord(handle, dataRecord);
                } else {
                    final var differ = new PropertyDiffer<>(existingDataRecord, dataRecord);
                    differ.diff("description", VulnerabilityDataRecord::description);
                    differ.diff("cwes", VulnerabilityDataRecord::cwes);
                    differ.diff("sourceCreatedAt", VulnerabilityDataRecord::sourceCreatedAt);
                    differ.diff("sourcePublishedAt", VulnerabilityDataRecord::sourcePublishedAt);
                    differ.diff("sourceUpdatedAt", VulnerabilityDataRecord::sourceUpdatedAt);
                    differ.diff("sourceRejectedAt", VulnerabilityDataRecord::sourceRejectedAt);

                    if (!differ.diffs().isEmpty()) {
                        LOGGER.info("{}: data has changed: {}", vulnId, differ.diffs());
                        updateDataRecord(handle, dataRecord);
                    } else {
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("{}: data has not changed", vulnId);
                        }
                    }
                }
            }

            final var ratingKeys = new HashSet<RatingIdentity>();
            ratingKeys.addAll(ratingRecordByIdentity.keySet());
            ratingKeys.addAll(existingRatingRecordByIdentity.keySet());

            for (final RatingIdentity ratingIdentity : ratingKeys) {
                final VulnerabilityRatingRecord ratingRecord = ratingRecordByIdentity.get(ratingIdentity);
                final VulnerabilityRatingRecord existingRatingRecord = existingRatingRecordByIdentity.get(ratingIdentity);

                if (ratingRecord == null) {
                    LOGGER.info("{}: deleting {} rating because it is no longer reported", ratingIdentity.vulnId(), ratingIdentity.method());
                    deleteRatingRecord(handle, ratingIdentity);
                } else if (existingRatingRecord == null) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("{}: creating {} rating", ratingIdentity.vulnId(), ratingIdentity.method());
                    }
                    createRatingRecord(handle, ratingRecord);
                } else {
                    final var differ = new PropertyDiffer<>(existingRatingRecord, ratingRecord);
                    differ.diff("severity", VulnerabilityRatingRecord::severity);
                    differ.diff("vector", VulnerabilityRatingRecord::vector);
                    differ.diff("score", VulnerabilityRatingRecord::score, (before, after) ->
                            // SQLite driver returns NaN for Double when the column was NULL...
                            Objects.equals(before, (after != null && !after.isNaN()) ? after : null));

                    if (!differ.diffs().isEmpty()) {
                        LOGGER.info("{}: {} rating has changed: {}", ratingIdentity.vulnId(), ratingIdentity.method(), differ.diffs());
                        updateRatingRecord(handle, ratingRecord);
                    } else {
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("{}: {} rating has not changed", ratingIdentity.vulnId(), ratingIdentity.method());
                        }
                    }
                }
            }

            final var referenceKeys = new HashSet<ReferenceIdentity>();
            referenceKeys.addAll(referenceRecordByIdentity.keySet());
            referenceKeys.addAll(existingReferenceRecordByIdentity.keySet());

            for (final ReferenceIdentity referenceIdentity : referenceKeys) {
                final VulnerabilityReferenceRecord referenceRecord = referenceRecordByIdentity.get(referenceIdentity);
                final VulnerabilityReferenceRecord existingReferenceRecord = existingReferenceRecordByIdentity.get(referenceIdentity);

                if (referenceRecord == null) {
                    LOGGER.info("{}: deleting reference {} because it is no longer reported", referenceIdentity.vulnId(), referenceIdentity.url());
                    deleteReferenceRecord(handle, referenceIdentity);
                } else if (existingReferenceRecord == null) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("{}: creating reference {}", referenceIdentity.vulnId(), referenceIdentity.url());
                    }
                    createReferenceRecord(handle, referenceRecord);
                } else {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("{}: reference {} has not changed", referenceIdentity.vulnId(), referenceIdentity.url());
                    }
                }
            }

            final var matchingCriteriaKeys = new HashSet<MatchingCriteriaIdentity>();
            matchingCriteriaKeys.addAll(matchingCriteriaRecordByIdentity.keySet());
            matchingCriteriaKeys.addAll(existingMatchingCriteriaRecordByIdentity.keySet());

            for (final MatchingCriteriaIdentity matchingCriteriaIdentity : matchingCriteriaKeys) {
                final MatchingCriteriaRecord matchingCriteriaRecord =
                        matchingCriteriaRecordByIdentity.get(matchingCriteriaIdentity);
                final MatchingCriteriaRecord existingMatchingCriteriaRecord =
                        existingMatchingCriteriaRecordByIdentity.get(matchingCriteriaIdentity);

                if (matchingCriteriaRecord == null) {
                    LOGGER.info("{}: deleting matching criteria because it is no longer reported: {}", matchingCriteriaIdentity.vulnId(), existingMatchingCriteriaRecord);
                    deleteMatchingCriteriaRecord(handle, existingMatchingCriteriaRecord.id());
                } else if (existingMatchingCriteriaRecord == null) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("{}: creating matching criteria because it was not reported before: {}", matchingCriteriaIdentity.vulnId(), matchingCriteriaRecord);
                    }
                    createMatchingCriteriaRecord(handle, matchingCriteriaRecord);
                } else {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("{}: matching criteria has not changed: {}", matchingCriteriaIdentity.vulnId(), matchingCriteriaRecord);
                    }
                }
            }
        });
    }

    private VulnerabilityRecord maybeCreateVulnerability(final Handle handle, final String vulnId) {
        final Query query = handle.createQuery("""
                insert into vuln(id) values(:vulnId)
                on conflict(id) do nothing
                returning *
                """);

        return query
                .bind("vulnId", vulnId)
                .map(ConstructorMapper.of(VulnerabilityRecord.class))
                .findOne()
                .orElse(null);
    }

    private Map<String, List<String>> getAliases(final Handle handle, final Collection<String> vulnIds) {
        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from vuln_alias
                 where source_name = :sourceName
                   and vuln_id in (<vulnIds>)
                   and deleted_at is null
                """);

        return query
                .bind("sourceName", source.name())
                .bindList("vulnIds", vulnIds)
                .map(ConstructorMapper.of(VulnerabilityAliasRecord.class))
                .stream()
                .collect(Collectors.groupingBy(
                        VulnerabilityAliasRecord::vulnId,
                        Collectors.mapping(VulnerabilityAliasRecord::aliasId, Collectors.toList())));
    }

    private void createAlias(final Handle handle, final String vulnId, final String aliasId) {
        final Update update = handle.createUpdate("""
                insert into vuln_alias(
                  source_name
                , vuln_id
                , alias_id
                ) values(
                  :sourceName
                , :vulnId
                , :aliasId
                )
                on conflict(source_name, vuln_id, alias_id) do update
                set deleted_at = null
                where vuln_alias.deleted_at is not null
                """);

        update
                .bind("sourceName", source.name())
                .bind("vulnId", vulnId)
                .bind("aliasId", aliasId)
                .execute();
    }

    private void deleteAlias(final Handle handle, final String vulnId, final String aliasId) {
        final Update update = handle.createUpdate("""
                update vuln_alias
                   set deleted_at = unixepoch()
                 where source_name = :sourceName
                   and vuln_id = :vulnId
                   and alias_id = :aliasId
                """);

        update
                .bind("sourceName", source.name())
                .bind("vulnId", vulnId)
                .bind("aliasId", aliasId)
                .execute();
    }

    private Map<String, VulnerabilityDataRecord> getDataRecords(final Handle handle, final Collection<String> vulnIds) {
        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from vuln_data
                 where source_name = :sourceName
                   and vuln_id in (<vulnIds>)
                """);

        return query
                .bind("sourceName", source.name())
                .bindList("vulnIds", vulnIds)
                .map(ConstructorMapper.of(VulnerabilityDataRecord.class))
                .stream()
                .collect(Collectors.toMap(
                        VulnerabilityDataRecord::vulnId,
                        Function.identity()));
    }

    private VulnerabilityDataRecord createDataRecord(
            final Handle handle,
            final VulnerabilityDataRecord dataRecord) {
        final Query query = handle.createQuery("""
                insert into vuln_data(
                  source_name
                , vuln_id
                , description
                , cwes
                , source_created_at
                , source_published_at
                , source_updated_at
                , source_rejected_at
                ) values(
                  :sourceName
                , :vulnId
                , :description
                , :cwes
                , :sourceCreatedAt
                , :sourcePublishedAt
                , :sourceUpdatedAt
                , :sourceRejectedAt
                )
                returning *
                """);

        return query
                .bindMethods(dataRecord)
                .map(ConstructorMapper.of(VulnerabilityDataRecord.class))
                .one();
    }

    private VulnerabilityDataRecord updateDataRecord(
            final Handle handle,
            final VulnerabilityDataRecord dataRecord) {
        final Query query = handle.createQuery("""
                update vuln_data
                   set description = :description
                     , cwes = :cwes
                     , source_created_at = :sourceCreatedAt
                     , source_published_at = :sourcePublishedAt
                     , source_updated_at = :sourceUpdatedAt
                     , source_rejected_at = :sourceRejectedAt
                     , updated_at = unixepoch()
                 where source_name = :sourceName
                   and vuln_id = :vulnId
                returning *
                """);

        return query
                .bind("sourceName", source.name())
                .bindMethods(dataRecord)
                .map(ConstructorMapper.of(VulnerabilityDataRecord.class))
                .one();
    }

    private record RatingIdentity(String vulnId, String method) {
    }

    private Map<RatingIdentity, VulnerabilityRatingRecord> getRatingRecords(
            final Handle handle,
            final Collection<String> vulnIds) {
        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from vuln_rating
                 where source_name = :sourceName
                   and vuln_id in (<vulnIds>)
                """);

        return query
                .bind("sourceName", source.name())
                .bindList("vulnIds", vulnIds)
                .map(ConstructorMapper.of(VulnerabilityRatingRecord.class))
                .stream()
                .collect(Collectors.toMap(
                        record -> new RatingIdentity(record.vulnId(), record.method()),
                        Function.identity()));
    }

    private VulnerabilityRatingRecord createRatingRecord(
            final Handle handle,
            final VulnerabilityRatingRecord dataRecord) {
        final Query query = handle.createQuery("""
                insert into vuln_rating(
                  source_name
                , vuln_id
                , method
                , severity
                , vector
                , score
                ) values(
                  :sourceName
                , :vulnId
                , :method
                , :severity
                , :vector
                , :score
                )
                returning *
                """);

        return query
                .bindMethods(dataRecord)
                .map(ConstructorMapper.of(VulnerabilityRatingRecord.class))
                .one();
    }

    private VulnerabilityRatingRecord updateRatingRecord(
            final Handle handle,
            final VulnerabilityRatingRecord ratingRecord) {
        final Query query = handle.createQuery("""
                update vuln_rating
                   set severity = :severity
                     , vector = :vector
                     , score = :score
                     , updated_at = unixepoch()
                 where source_name = :sourceName
                   and vuln_id = :vulnId
                   and method = :method
                returning *
                """);

        return query
                .bind("sourceName", source.name())
                .bindMethods(ratingRecord)
                .map(ConstructorMapper.of(VulnerabilityRatingRecord.class))
                .one();
    }

    private void deleteRatingRecord(final Handle handle, final RatingIdentity ratingIdentity) {
        final Update update = handle.createUpdate("""
                delete
                  from vuln_rating
                 where source_name = :sourceName
                   and vuln_id = :vulnId
                   and method = :method
                """);

        update
                .bind("sourceName", source.name())
                .bind("vulnId", ratingIdentity.vulnId())
                .bind("method", ratingIdentity.method())
                .execute();
    }

    private record ReferenceIdentity(String vulnId, String url) {
    }

    private Map<ReferenceIdentity, VulnerabilityReferenceRecord> getReferenceRecords(
            final Handle handle,
            final Collection<String> vulnIds) {
        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from vuln_reference
                 where source_name = :sourceName
                   and vuln_id in (<vulnIds>)
                """);

        return query
                .bind("sourceName", source.name())
                .bindList("vulnIds", vulnIds)
                .map(ConstructorMapper.of(VulnerabilityReferenceRecord.class))
                .stream()
                .collect(Collectors.toMap(
                        record -> new ReferenceIdentity(record.vulnId(), record.url()),
                        Function.identity()));
    }

    private VulnerabilityReferenceRecord createReferenceRecord(
            final Handle handle,
            final VulnerabilityReferenceRecord referenceRecord) {
        final Query query = handle.createQuery("""
                insert into vuln_reference(
                  source_name
                , vuln_id
                , url
                , name
                ) values(
                  :sourceName
                , :vulnId
                , :url
                , :name
                )
                returning *
                """);

        return query
                .bindMethods(referenceRecord)
                .map(ConstructorMapper.of(VulnerabilityReferenceRecord.class))
                .one();
    }

    private void deleteReferenceRecord(final Handle handle, final ReferenceIdentity referenceIdentity) {
        final Update update = handle.createUpdate("""
                delete
                  from vuln_reference
                 where source_name = :sourceName
                   and vuln_id = :vulnId
                   and url = :url
                """);

        update
                .bind("sourceName", source.name())
                .bind("vulnId", referenceIdentity.vulnId())
                .bind("url", referenceIdentity.url())
                .execute();
    }

    // Same fields as MatchingCriteriaRecord, but omits id, source, and created_at.
    private record MatchingCriteriaIdentity(
            String vulnId,
            String cpe,
            String cpePart,
            String cpeVendor,
            String cpeProduct,
            String purlType,
            String purlNamespace,
            String purlName,
            String versions,
            String additionalCriteriaType,
            ByteBuffer additionalCriteria) {

        private static MatchingCriteriaIdentity of(final MatchingCriteriaRecord record) {
            return new MatchingCriteriaIdentity(
                    record.vulnId(),
                    record.cpe(),
                    record.cpePart(),
                    record.cpeVendor(),
                    record.cpeProduct(),
                    record.purlType(),
                    record.purlNamespace(),
                    record.purlName(),
                    record.versions(),
                    record.additionalCriteriaType(),
                    // equals and hashCode implementations of record classes
                    // don't take array content into consideration.
                    // Wrap in a ByteBuffer to sidestep this limitation.
                    record.additionalCriteria() != null
                            ? ByteBuffer.wrap(record.additionalCriteria())
                            : null);
        }

    }

    private Map<MatchingCriteriaIdentity, MatchingCriteriaRecord> getMatchingCriteriaRecords(
            final Handle handle,
            final Collection<String> vulnIds) {
        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from matching_criteria
                 where source_name = :sourceName
                   and vuln_id in (<vulnIds>)
                """);

        return query
                .bind("sourceName", source.name())
                .bindList("vulnIds", vulnIds)
                .map(ConstructorMapper.of(MatchingCriteriaRecord.class))
                .stream()
                .collect(Collectors.toMap(
                        MatchingCriteriaIdentity::of,
                        Function.identity()));
    }

    private MatchingCriteriaRecord createMatchingCriteriaRecord(
            final Handle handle,
            final MatchingCriteriaRecord matchingCriteriaRecord) {
        final Query query = handle.createQuery("""
                insert into matching_criteria(
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
                ) values(
                  :sourceName
                , :vulnId
                , :cpe
                , :cpePart
                , :cpeVendor
                , :cpeProduct
                , :purlType
                , :purlNamespace
                , :purlName
                , :versions
                , :additionalCriteriaType
                , :additionalCriteria
                )
                returning *
                """);

        return query
                .bindMethods(matchingCriteriaRecord)
                .map(ConstructorMapper.of(MatchingCriteriaRecord.class))
                .one();
    }

    private void deleteMatchingCriteriaRecord(final Handle handle, final long matchingCriteriaId) {
        if (matchingCriteriaId <= 0) {
            throw new IllegalArgumentException("Invalid matching criteria id: " + matchingCriteriaId);
        }

        final Update update = handle.createUpdate("""
                delete
                  from matching_criteria
                 where id = :id
                """);

        update
                .bind("id", matchingCriteriaId)
                .execute();
    }

}

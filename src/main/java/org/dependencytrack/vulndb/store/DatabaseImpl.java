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
import java.nio.file.Path;
import java.util.ArrayList;
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
                    insert into source(name, license, url)
                    values (:name, :license, :url)
                    on conflict (name) do update
                    set license = :license
                      , url = :url
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
        final var dataRecordById = new HashMap<String, VulnerabilityDataRecord>(vulns.size());
        final var ratingRecordByKey = new HashMap<RatingKey, VulnerabilityRatingRecord>(vulns.size());
        final var referenceRecordByKey = new HashMap<ReferenceKey, VulnerabilityReferenceRecord>(vulns.size());
        final var matchingCriteriaRecordsByVulnId = new HashMap<String, List<MatchingCriteriaRecord>>();

        for (final Vulnerability vuln : vulns) {
            vulnIds.add(vuln.id());

            if (vuln.aliases() != null) {
                aliasesByVulnId.put(vuln.id(), vuln.aliases());
            }

            dataRecordById.put(vuln.id(), VulnerabilityDataRecord.of(source, vuln));

            if (vuln.ratings() != null) {
                for (final Rating rating : vuln.ratings()) {
                    ratingRecordByKey.put(
                            new RatingKey(vuln.id(), rating.method().name().replace("_", ".")),
                            VulnerabilityRatingRecord.of(source, vuln.id(), rating));
                }
            }

            if (vuln.references() != null) {
                for (final Reference reference : vuln.references()) {
                    referenceRecordByKey.put(
                            new ReferenceKey(vuln.id(), reference.url()),
                            VulnerabilityReferenceRecord.of(source, vuln.id(), reference));
                }
            }

            if (vuln.matchingCriteria() != null) {
                for (final MatchingCriteria matchingCriteria : vuln.matchingCriteria()) {
                    matchingCriteriaRecordsByVulnId
                            .computeIfAbsent(vuln.id(), ignored -> new ArrayList<>())
                            .add(MatchingCriteriaRecord.of(source, vuln.id(), matchingCriteria));
                }
            }
        }

        jdbi.useTransaction(handle -> {
            final Map<String, List<String>> existingAliasesByVulnId =
                    getAliases(handle, vulnIds);
            final Map<String, VulnerabilityDataRecord> existingDataRecordByVulnId =
                    getDataRecords(handle, vulnIds);
            final Map<RatingKey, VulnerabilityRatingRecord> existingRatingRecordByKey =
                    getRatingRecords(handle, vulnIds);
            final Map<ReferenceKey, VulnerabilityReferenceRecord> existingReferenceRecordByKey =
                    getReferenceRecords(handle, vulnIds);
            final Map<String, List<MatchingCriteriaRecord>> existingMatchingCriteriaRecordsByVulnId =
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
                    LOGGER.debug("Creating alias {} for {} because it was not reported before", aliasId, vulnId);
                    createAlias(handle, vulnId, aliasId);
                }
                for (final String aliasId : aliasesToDelete) {
                    LOGGER.debug("Deleting alias {} for {} because it is no longer reported", aliasId, vulnId);
                    deleteAlias(handle, vulnId, aliasId);
                }

                final VulnerabilityDataRecord dataRecord = dataRecordById.get(vulnId);
                final VulnerabilityDataRecord existingDataRecord = existingDataRecordByVulnId.get(vulnId);
                if (existingDataRecord == null) {
                    createDataRecord(handle, dataRecord);
                } else {
                    boolean hasChanged = false;
                    hasChanged |= !Objects.equals(dataRecord.description(), existingDataRecord.description());
                    hasChanged |= !Objects.equals(dataRecord.cwes(), existingDataRecord.cwes());
                    hasChanged |= !Objects.equals(dataRecord.sourceCreatedAt(), existingDataRecord.sourceCreatedAt());
                    hasChanged |= !Objects.equals(dataRecord.sourcePublishedAt(), existingDataRecord.sourcePublishedAt());
                    hasChanged |= !Objects.equals(dataRecord.sourceUpdatedAt(), existingDataRecord.sourceUpdatedAt());
                    hasChanged |= !Objects.equals(dataRecord.sourceRejectedAt(), existingDataRecord.sourceRejectedAt());

                    if (hasChanged) {
                        LOGGER.info("Updating data for {} because it changed", vulnId);
                        updateDataRecord(handle, dataRecord);
                    } else {
                        LOGGER.debug("Data for {} has not changed", vulnId);
                    }
                }

                final List<MatchingCriteriaRecord> matchingCriteriaRecords = matchingCriteriaRecordsByVulnId.get(vulnId);
                final List<MatchingCriteriaRecord> existingMatchingCriteriaRecords = existingMatchingCriteriaRecordsByVulnId.get(vulnId);
                if (existingMatchingCriteriaRecords == null || existingMatchingCriteriaRecords.isEmpty()) {
                    if (matchingCriteriaRecords != null) {
                        for (final MatchingCriteriaRecord matchingCriteriaRecord : matchingCriteriaRecords) {
                            createMatchingCriteriaRecord(handle, matchingCriteriaRecord);
                        }
                    }
                }
            }

            final var ratingKeys = new HashSet<RatingKey>();
            ratingKeys.addAll(ratingRecordByKey.keySet());
            ratingKeys.addAll(existingRatingRecordByKey.keySet());

            for (final RatingKey ratingKey : ratingKeys) {
                final VulnerabilityRatingRecord ratingRecord = ratingRecordByKey.get(ratingKey);
                final VulnerabilityRatingRecord existingRatingRecord = existingRatingRecordByKey.get(ratingKey);

                if (ratingRecord == null) {
                    LOGGER.debug("Deleting rating with {} because it is no longer reported", ratingKey);
                    deleteRatingRecord(handle, ratingKey);
                } else if (existingRatingRecord == null) {
                    LOGGER.debug("Creating rating with {} because it was not reported before", ratingKey);
                    createRatingRecord(handle, ratingRecord);
                } else {
                    boolean hasChanged = false;
                    hasChanged |= !Objects.equals(ratingRecord.severity(), existingRatingRecord.severity());
                    hasChanged |= !Objects.equals(ratingRecord.vector(), existingRatingRecord.vector());
                    hasChanged |= !Objects.equals(ratingRecord.score(),
                            // SQLite driver returns NaN for Double when the column was NULL...
                            (existingRatingRecord.score() != null && !existingRatingRecord.score().isNaN())
                                    ? existingRatingRecord.score()
                                    : null);

                    if (hasChanged) {
                        LOGGER.info("Updating rating with {} because it changed", ratingKey);
                        updateRatingRecord(handle, ratingRecord);
                    } else {
                        LOGGER.debug("Rating with {} has not changed", ratingKey);
                    }
                }
            }

            final var referenceKeys = new HashSet<ReferenceKey>();
            referenceKeys.addAll(referenceRecordByKey.keySet());
            referenceKeys.addAll(existingReferenceRecordByKey.keySet());

            for (final ReferenceKey referenceKey : referenceKeys) {
                final VulnerabilityReferenceRecord referenceRecord = referenceRecordByKey.get(referenceKey);
                final VulnerabilityReferenceRecord existingReferenceRecord = existingReferenceRecordByKey.get(referenceKey);

                if (referenceRecord == null) {
                    LOGGER.debug("Deleting reference with {} because it is no longer reported", referenceKey);
                    deleteReferenceRecord(handle, referenceKey);
                } else if (existingReferenceRecord == null) {
                    LOGGER.debug("Creating reference with {} because it was not reported before", referenceKey);
                    createReferenceRecord(handle, referenceRecord);
                } else {
                    LOGGER.debug("Reference with {} has not changed", referenceKey);
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
                 where source_name = :source.name
                   and vuln_id in (<vulnIds>)
                   and deleted_at is null
                """);

        return query
                .bindMethods("source", source)
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
                  :source.name
                , :vulnId
                , :aliasId
                )
                on conflict(source_name, vuln_id, alias_id) do update
                set deleted_at = null
                where vuln_alias.deleted_at is not null
                """);

        update
                .bindMethods("source", source)
                .bind("vulnId", vulnId)
                .bind("aliasId", aliasId)
                .execute();
    }

    private void deleteAlias(final Handle handle, final String vulnId, final String aliasId) {
        final Update update = handle.createUpdate("""
                update vuln_alias
                   set deleted_at = unixepoch()
                 where source_name = :source.name
                   and vuln_id = :vulnId
                   and alias_id = :aliasId
                """);

        update
                .bindMethods("source", source)
                .bind("vulnId", vulnId)
                .bind("aliasId", aliasId)
                .execute();
    }

    private Map<String, VulnerabilityDataRecord> getDataRecords(final Handle handle, final Collection<String> vulnIds) {
        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from vuln_data
                 where source_name = :source.name
                   and vuln_id in (<vulnIds>)
                """);

        return query
                .bindMethods("source", source)
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
                 where source_name = :source.name
                   and vuln_id = :vulnId
                returning *
                """);

        return query
                .bindMethods("source", source)
                .bindMethods(dataRecord)
                .map(ConstructorMapper.of(VulnerabilityDataRecord.class))
                .one();
    }

    private record RatingKey(String vulnId, String method) {
    }

    private Map<RatingKey, VulnerabilityRatingRecord> getRatingRecords(
            final Handle handle,
            final Collection<String> vulnIds) {
        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from vuln_rating
                 where source_name = :source.name
                   and vuln_id in (<vulnIds>)
                """);

        return query
                .bindMethods("source", source)
                .bindList("vulnIds", vulnIds)
                .map(ConstructorMapper.of(VulnerabilityRatingRecord.class))
                .stream()
                .collect(Collectors.toMap(
                        record -> new RatingKey(record.vulnId(), record.method()),
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
                 where source_name = :source.name
                   and vuln_id = :vulnId
                   and method = :method
                returning *
                """);

        return query
                .bindMethods("source", source)
                .bindMethods(ratingRecord)
                .map(ConstructorMapper.of(VulnerabilityRatingRecord.class))
                .one();
    }

    private void deleteRatingRecord(final Handle handle, final RatingKey ratingKey) {
        final Update update = handle.createUpdate("""
                delete
                  from vuln_rating
                 where source_name = :source.name
                   and vuln_id = :vulnId
                   and method = :method
                """);

        update
                .bindMethods("source", source)
                .bindMethods(ratingKey)
                .execute();
    }

    private record ReferenceKey(String vulnId, String url) {
    }

    private Map<ReferenceKey, VulnerabilityReferenceRecord> getReferenceRecords(
            final Handle handle,
            final Collection<String> vulnIds) {
        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from vuln_reference
                 where source_name = :source.name
                   and vuln_id in (<vulnIds>)
                """);

        return query
                .bindMethods("source", source)
                .bindList("vulnIds", vulnIds)
                .map(ConstructorMapper.of(VulnerabilityReferenceRecord.class))
                .stream()
                .collect(Collectors.toMap(
                        record -> new ReferenceKey(record.vulnId(), record.url()),
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

    private void deleteReferenceRecord(final Handle handle, final ReferenceKey referenceKey) {
        final Update update = handle.createUpdate("""
                delete
                  from vuln_reference
                 where source_name = :source.name
                   and vuln_id = :vulnId
                   and url = :url
                """);

        update
                .bindMethods("source", source)
                .bindMethods(referenceKey)
                .execute();
    }

    private Map<String, List<MatchingCriteriaRecord>> getMatchingCriteriaRecords(
            final Handle handle,
            final Collection<String> vulnIds) {
        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from matching_criteria
                 where source_name = :source.name
                   and vuln_id in (<vulnIds>)
                """);

        return query
                .bindMethods("source", source)
                .bindList("vulnIds", vulnIds)
                .map(ConstructorMapper.of(MatchingCriteriaRecord.class))
                .stream()
                .collect(Collectors.groupingBy(
                        MatchingCriteriaRecord::vulnId,
                        Collectors.toList()));
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

}

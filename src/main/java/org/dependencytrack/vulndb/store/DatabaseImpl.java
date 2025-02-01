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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class DatabaseImpl implements Database, Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseImpl.class);

    private final Jdbi jdbi;
    private final Source source;

    private DatabaseImpl(final Jdbi jdbi, final Source source) {
        this.jdbi = jdbi;
        this.source = source;
    }

    public static DatabaseImpl forSource(final Source source) {
        final var jdbi = Jdbi
                .create("jdbc:sqlite:%s.db".formatted(source.name()))
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
        final var aliasRecordsByVulnId = new HashMap<String, List<VulnerabilityAliasRecord>>();
        final var dataRecordById = new HashMap<String, VulnerabilityDataRecord>(vulns.size());
        final var ratingRecordByKey = new HashMap<RatingKey, VulnerabilityRatingRecord>(vulns.size());
        final var referenceRecordByKey = new HashMap<ReferenceKey, VulnerabilityReferenceRecord>(vulns.size());
        final var matchingCriteriaRecordsByVulnId = new HashMap<String, List<MatchingCriteriaRecord>>();

        for (final Vulnerability vuln : vulns) {
            vulnIds.add(vuln.id());

            if (vuln.aliases() != null) {
                aliasRecordsByVulnId
                        .computeIfAbsent(vuln.id(), ignored -> new ArrayList<>())
                        .addAll(vuln.aliases().stream()
                                .map(aliasId -> new VulnerabilityAliasRecord(
                                        source.name(),
                                        vuln.id(),
                                        aliasId,
                                        null,
                                        null))
                                .toList());
            }

            dataRecordById.put(vuln.id(), new VulnerabilityDataRecord(
                    source.name(),
                    vuln.id(),
                    vuln.description(),
                    vuln.cwes(),
                    vuln.createdAt(),
                    vuln.publishedAt(),
                    vuln.updatedAt(),
                    null,
                    null,
                    vuln.rejectedAt()));

            if (vuln.ratings() != null) {
                for (final Rating rating : vuln.ratings()) {
                    ratingRecordByKey.put(
                            new RatingKey(vuln.id(), rating.method().name().replace("_", ".")),
                            new VulnerabilityRatingRecord(
                                    source.name(),
                                    vuln.id(),
                                    rating.method().name().replace("_", "."),
                                    rating.severity().name().toLowerCase(),
                                    rating.vector(),
                                    rating.score(),
                                    null,
                                    null));
                }
            }

            if (vuln.references() != null) {
                for (final Reference reference : vuln.references()) {
                    referenceRecordByKey.put(
                            new ReferenceKey(vuln.id(), reference.url()),
                            new VulnerabilityReferenceRecord(
                                    source.name(),
                                    vuln.id(),
                                    reference.url(),
                                    reference.name()));
                }
            }

            if (vuln.matchingCriteria() != null) {
                for (final MatchingCriteria matchingCriteria : vuln.matchingCriteria()) {
                    matchingCriteriaRecordsByVulnId
                            .computeIfAbsent(vuln.id(), ignored -> new ArrayList<>())
                            .add(new MatchingCriteriaRecord(
                                    -1,
                                    source.name(),
                                    vuln.id(),
                                    matchingCriteria.cpe() != null
                                            ? matchingCriteria.cpe().toCpe23FS()
                                            : null,
                                    matchingCriteria.cpe() != null
                                            ? matchingCriteria.cpe().getPart().getAbbreviation().toLowerCase()
                                            : null,
                                    matchingCriteria.cpe() != null
                                            ? matchingCriteria.cpe().getVendor().toLowerCase()
                                            : null,
                                    matchingCriteria.cpe() != null
                                            ? matchingCriteria.cpe().getProduct().toLowerCase()
                                            : null,
                                    matchingCriteria.purl() != null
                                            ? matchingCriteria.purl().getType()
                                            : null,
                                    matchingCriteria.purl() != null
                                            ? matchingCriteria.purl().getNamespace()
                                            : null,
                                    matchingCriteria.purl() != null
                                            ? matchingCriteria.purl().getName()
                                            : null,
                                    matchingCriteria.versions() != null
                                            ? matchingCriteria.versions().toString()
                                            : null,
                                    matchingCriteria.additionalCriteriaType(),
                                    matchingCriteria.additionalCriteria(),
                                    null,
                                    null));
                }
            }
        }

        jdbi.useTransaction(handle -> {
            final Map<String, List<VulnerabilityAliasRecord>> existingAliasRecordsByVulnId =
                    getAliasRecords(handle, vulnIds);
            final Map<String, VulnerabilityDataRecord> existingDataRecordById =
                    getDataRecords(handle, vulnIds);
            final Map<RatingKey, VulnerabilityRatingRecord> existingRatingRecordByKey =
                    getRatingRecords(handle, vulnIds);
            final Map<ReferenceKey, VulnerabilityReferenceRecord> existingReferenceRecordByKey =
                    getReferenceRecords(handle, vulnIds);
            final Map<String, List<MatchingCriteriaRecord>> existingMatchingCriteriaRecordsByVulnId =
                    getMatchingCriteriaRecords(handle, vulnIds);

            for (final String vulnId : vulnIds) {
                maybeCreateVulnerability(handle, vulnId);

                final List<VulnerabilityAliasRecord> aliasRecords = aliasRecordsByVulnId.get(vulnId);
                final List<VulnerabilityAliasRecord> existingAliasRecords = existingAliasRecordsByVulnId.get(vulnId);
                if (existingAliasRecords == null || existingAliasRecords.isEmpty()) {
                    if (aliasRecords != null) {
                        for (final VulnerabilityAliasRecord aliasRecord : aliasRecords) {
                            createAliasRecord(handle, aliasRecord);
                        }
                    }
                }

                final VulnerabilityDataRecord dataRecord = dataRecordById.get(vulnId);
                final VulnerabilityDataRecord existingDataRecord = existingDataRecordById.get(vulnId);
                if (existingDataRecord == null) {
                    createDataRecord(handle, dataRecord);
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

            for (final RatingKey ratingKey : ratingRecordByKey.keySet()) {
                final VulnerabilityRatingRecord ratingRecord = ratingRecordByKey.get(ratingKey);
                final VulnerabilityRatingRecord existingRatingRecord = existingRatingRecordByKey.get(ratingKey);
                if (existingRatingRecord == null) {
                    createRatingRecord(handle, ratingRecord);
                }
            }

            for (final ReferenceKey referenceKey : referenceRecordByKey.keySet()) {
                final VulnerabilityReferenceRecord referenceRecord = referenceRecordByKey.get(referenceKey);
                final VulnerabilityReferenceRecord existingReferenceRecord = existingReferenceRecordByKey.get(referenceKey);
                if (existingReferenceRecord == null) {
                    createReferenceRecord(handle, referenceRecord);
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

    private Map<String, List<VulnerabilityAliasRecord>> getAliasRecords(final Handle handle, final Collection<String> vulnIds) {
        final Query query = handle.createQuery(/* language=SQL */ """
                select *
                  from vuln_alias
                 where source_name = :source.name
                   and vuln_id in (<vulnIds>)
                """);

        return query
                .bindMethods("source", source)
                .bindList("vulnIds", vulnIds)
                .map(ConstructorMapper.of(VulnerabilityAliasRecord.class))
                .stream()
                .collect(Collectors.groupingBy(
                        VulnerabilityAliasRecord::vulnId,
                        Collectors.toList()));
    }

    private VulnerabilityAliasRecord createAliasRecord(final Handle handle, final VulnerabilityAliasRecord aliasRecord) {
        final Query query = handle.createQuery("""
                insert into vuln_alias(
                  source_name
                , vuln_id
                , alias_id
                ) values(
                  :sourceName
                , :vulnId
                , :aliasId
                )
                RETURNING *
                """);

        return query
                .bindMethods(aliasRecord)
                .map(ConstructorMapper.of(VulnerabilityAliasRecord.class))
                .one();
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
                ) values(
                  :sourceName
                , :vulnId
                , :description
                , :cwes
                , :sourceCreatedAt
                , :sourcePublishedAt
                , :sourceUpdatedAt
                )
                RETURNING *
                """);

        return query
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
                RETURNING *
                """);

        return query
                .bindMethods(dataRecord)
                .map(ConstructorMapper.of(VulnerabilityRatingRecord.class))
                .one();
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
                RETURNING *
                """);

        return query
                .bindMethods(referenceRecord)
                .map(ConstructorMapper.of(VulnerabilityReferenceRecord.class))
                .one();
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
                RETURNING *
                """);

        return query
                .bindMethods(matchingCriteriaRecord)
                .map(ConstructorMapper.of(MatchingCriteriaRecord.class))
                .one();
    }

}

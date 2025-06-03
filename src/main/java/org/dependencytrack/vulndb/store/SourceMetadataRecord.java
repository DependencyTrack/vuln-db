package org.dependencytrack.vulndb.store;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

public record SourceMetadataRecord(
        String sourceName,
        String key,
        String value,
        Instant createdAt,
        @Nullable Instant updatedAt) {
}

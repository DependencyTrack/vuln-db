package org.dependencytrack.vulndb.store;

import jakarta.annotation.Nullable;
import java.time.Instant;

public record SourceMetadataRecord(
        String sourceName,
        String key,
        String value,
        Instant createdAt,
        @Nullable Instant updatedAt) {
}

package org.dependencytrack.vulndb.store;

import java.time.Instant;

public record MatchingCriteriaRecord(
        long id,
        String sourceName,
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
        byte[] additionalCriteria,
        Instant createdAt,
        Instant updatedAt) {
}

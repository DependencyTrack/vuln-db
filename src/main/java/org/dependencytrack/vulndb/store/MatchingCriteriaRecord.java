package org.dependencytrack.vulndb.store;

import org.dependencytrack.vulndb.api.MatchingCriteria;
import org.dependencytrack.vulndb.api.Source;

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

    static MatchingCriteriaRecord of(final Source source, final String vulnId, final MatchingCriteria matchingCriteria) {
        return new MatchingCriteriaRecord(
                -1,
                source.name(),
                vulnId,
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
                null);
    }

}

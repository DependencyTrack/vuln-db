package org.dependencytrack.vulndb.api;

import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.Vers;
import us.springett.parsers.cpe.Cpe;

public record MatchingCriteria(
        Cpe cpe,
        PackageURL purl,
        Vers versions,
        String additionalCriteriaType,
        byte[] additionalCriteria) {
}

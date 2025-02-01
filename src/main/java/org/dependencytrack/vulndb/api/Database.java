package org.dependencytrack.vulndb.api;

import java.util.Collection;
import java.util.Map;

public interface Database {

    Map<String, String> getSourceMetadata();

    void putSourceMetadata(final String key, final String value);

    void storeVulnerabilities(Collection<Vulnerability> vulns);

}

package org.dependencytrack.vulndb.source.euvd;

import java.util.List;

public record EuvdVulnerabilitiesPage(List<EuvdVulnerability> items, int total) {
}

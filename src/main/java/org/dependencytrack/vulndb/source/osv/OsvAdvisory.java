package org.dependencytrack.vulndb.source.osv;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public record OsvAdvisory(
        @JsonProperty("schema_version") String schemaVersion,
        String id,
        List<String> aliases,
        List<String> related,
        String summary,
        String details,
        Instant published,
        Instant modified,
        Instant withdrawn,
        List<Severity> severity,
        List<Affected> affected,
        List<Reference> references,
        List<Credit> credits,
        @JsonProperty("database_specific") Map<String, Object> databaseSpecific) {

    public record Affected(
            @JsonProperty("package") Package pkg,
            List<Severity> severity,
            List<Range> ranges,
            List<String> versions,
            @JsonProperty("database_specific") Map<String, Object> databaseSpecific,
            @JsonProperty("ecosystem_specific") Map<String, Object> ecosystemSpecific) {
    }

    public record Credit(
            String name,
            List<String> contact,
            String type) {
    }

    public record Package(
            String ecosystem,
            String name,
            String purl) {
    }

    public record Range(
            String type,
            String repo,
            List<Event> events,
            @JsonProperty("database_specific") Map<String, Object> databaseSpecific) {

        public record Event(
                String introduced,
                String fixed,
                @JsonProperty("last_affected") String lastAffected,
                String limit) {
        }

        List<Map.Entry<String, String>> genericEvents() {
            if (events == null || events.isEmpty()) {
                return Collections.emptyList();
            }

            return events.stream()
                    .map(event -> {
                        if (event.introduced != null) {
                            return Map.entry("introduced", event.introduced);
                        } else if (event.fixed != null) {
                            return Map.entry("fixed", event.fixed);
                        } else if (event.lastAffected != null) {
                            return Map.entry("last_affected", event.lastAffected);
                        } else if (event.limit != null) {
                            return Map.entry("limit", event.limit);
                        } else {
                            throw new IllegalStateException();
                        }
                    })
                    .toList();
        }

    }

    public record Reference(String type, String url) {
    }

    public record Severity(String type, String score) {
    }

}

package org.dependencytrack.vulndb.api;

import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

public record Source(String name, String displayName, String license, String url) {

    private static final Pattern NAME_PATTERN = Pattern.compile("^[a-z0-9]+$");

    public Source {
        requireNonNull(name, "name must not be null");
        requireNonNull(displayName, "displayName must not be null");
        if (!NAME_PATTERN.matcher(name).matches()) {
            throw new IllegalArgumentException("name must match " + NAME_PATTERN.pattern());
        }
    }

}

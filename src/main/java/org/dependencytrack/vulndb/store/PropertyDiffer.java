package org.dependencytrack.vulndb.store;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Function;

final class PropertyDiffer<T> {

    record Diff(Object before, Object after) {
    }

    private final T beforeObject;
    private final T afterObject;
    private final Map<String, Diff> diffByPropertyName = new HashMap<>();

    PropertyDiffer(final T beforeObject, final T afterObject) {
        this.beforeObject = beforeObject;
        this.afterObject = afterObject;
    }

    <V> boolean diff(
            final String propertyName,
            final Function<T, V> getter,
            final BiFunction<V, V, Boolean> isEqualBiFunction) {
        final V before = getter.apply(beforeObject);
        final V after = getter.apply(afterObject);

        if (!isEqualBiFunction.apply(before, after)) {
            diffByPropertyName.put(propertyName, new Diff(before, after));
            return true;
        }

        return false;
    }

    <V> boolean diff(final String propertyName, final Function<T, V> getter) {
        return diff(propertyName, getter, Objects::equals);
    }

    Map<String, Diff> diffs() {
        return Collections.unmodifiableMap(diffByPropertyName);
    }

}

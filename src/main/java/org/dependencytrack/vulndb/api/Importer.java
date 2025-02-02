package org.dependencytrack.vulndb.api;

import java.io.Closeable;

public interface Importer extends Closeable {

    void runImport() throws Exception;

    @Override
    default void close() {
    }

}

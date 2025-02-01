package org.dependencytrack.vulndb.api;

import java.io.Closeable;

public interface Importer extends Closeable {

    void runImport();

    @Override
    default void close() {
    }
    
}

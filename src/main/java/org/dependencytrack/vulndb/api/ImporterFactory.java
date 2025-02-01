package org.dependencytrack.vulndb.api;

public interface ImporterFactory {

    Source source();

    void init(final Database database);

    Importer createImporter();

}

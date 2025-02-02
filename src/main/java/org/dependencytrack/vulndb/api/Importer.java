package org.dependencytrack.vulndb.api;

public interface Importer {

    Source source();

    void init(final Database database);

    void runImport() throws Exception;

}

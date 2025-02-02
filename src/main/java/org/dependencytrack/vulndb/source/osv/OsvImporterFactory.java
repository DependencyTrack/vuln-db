package org.dependencytrack.vulndb.source.osv;

import org.dependencytrack.vulndb.api.Database;
import org.dependencytrack.vulndb.api.Importer;
import org.dependencytrack.vulndb.api.ImporterFactory;
import org.dependencytrack.vulndb.api.Source;

public final class OsvImporterFactory implements ImporterFactory {

    private Database database;

    @Override
    public Source source() {
        return new Source("OSV", "", "https://osv.dev/");
    }

    @Override
    public void init(final Database database) {
        this.database = database;
    }

    @Override
    public Importer createImporter() {
        return new OsvImporter(database);
    }

}

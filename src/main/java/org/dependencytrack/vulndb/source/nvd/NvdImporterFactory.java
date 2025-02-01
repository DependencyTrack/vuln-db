package org.dependencytrack.vulndb.source.nvd;

import org.dependencytrack.vulndb.api.Database;
import org.dependencytrack.vulndb.api.Importer;
import org.dependencytrack.vulndb.api.ImporterFactory;
import org.dependencytrack.vulndb.api.Source;

public class NvdImporterFactory implements ImporterFactory {

    private Database database;

    @Override
    public Source source() {
        return new Source("NVD", null, "https://nvd.nist.gov/");
    }

    @Override
    public void init(final Database database) {
        this.database = database;
    }

    @Override
    public Importer createImporter() {
        return new NvdImporter(database);
    }

}

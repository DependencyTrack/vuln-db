package org.dependencytrack.vulndb.source.github;

import org.dependencytrack.vulndb.api.Database;
import org.dependencytrack.vulndb.api.Importer;
import org.dependencytrack.vulndb.api.ImporterFactory;
import org.dependencytrack.vulndb.api.Source;

public class GitHubImporterFactory implements ImporterFactory {

    private Database database;

    @Override
    public Source source() {
        return new Source("GitHub", "CC-BY-4.0", "https://github.com/advisories");
    }

    @Override
    public void init(final Database database) {
        this.database = database;
    }

    @Override
    public Importer createImporter() {
        return new GitHubImporter(database);
    }

}

package org.dependencytrack.vulndb;

import org.dependencytrack.vulndb.api.Importer;
import org.dependencytrack.vulndb.api.ImporterFactory;
import org.dependencytrack.vulndb.store.DatabaseImpl;
import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Application {

    private static final Set<String> ENABLED_SOURCES = Set.of("GitHub", "NVD");

    public static void main(final String[] args) {
        final var importTasks = new ArrayList<ImportTask>();
        for (final ImporterFactory importerFactory : ServiceLoader.load(ImporterFactory.class)) {
            if (!ENABLED_SOURCES.contains(importerFactory.source().name())) {
                continue;
            }

            final var database = DatabaseImpl.forSource(importerFactory.source());
            importerFactory.init(database);
            importTasks.add(new ImportTask(importerFactory));
        }

        final ExecutorService executorService = Executors.newFixedThreadPool(importTasks.size());
        try (executorService) {
            for (final ImportTask importTask : importTasks) {
                executorService.execute(importTask);
            }
        }
    }

    private static final class ImportTask implements Runnable {

        private final ImporterFactory importerFactory;

        public ImportTask(final ImporterFactory importerFactory) {
            this.importerFactory = importerFactory;
        }

        @Override
        public void run() {
            try (final Importer importer = importerFactory.createImporter();
                 var ignoredMdcSource = MDC.putCloseable("source", importerFactory.source().name())) {
                importer.runImport();
            }
        }

    }

}

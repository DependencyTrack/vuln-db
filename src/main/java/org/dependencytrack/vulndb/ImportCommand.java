package org.dependencytrack.vulndb;

import org.dependencytrack.vulndb.api.Importer;
import org.dependencytrack.vulndb.api.ImporterFactory;
import org.dependencytrack.vulndb.store.DatabaseImpl;
import org.slf4j.MDC;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.ArrayList;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Command(name = "import")
public class ImportCommand implements Callable<Integer> {

    @Option(names = "-source", description = "Sources to import data from")
    Set<String> sources;

    @Override
    public Integer call() {
        if (sources == null || sources.isEmpty()) {
            throw new IllegalArgumentException("No sources specified");
        }

        final var importTasks = new ArrayList<ImportTask>();
        for (final ImporterFactory importerFactory : ServiceLoader.load(ImporterFactory.class)) {
            if (!sources.contains(importerFactory.source().name())) {
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

        return 0;
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
            } catch (Exception e) {
                throw new RuntimeException("Importer for source %s failed".formatted(
                        importerFactory.source().name()), e);
            }
        }

    }

}

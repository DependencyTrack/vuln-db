package org.dependencytrack.vulndb;

import org.dependencytrack.vulndb.api.Importer;
import org.dependencytrack.vulndb.store.DatabaseImpl;
import org.slf4j.MDC;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Command(name = "import", description = "Import data from upstream sources.")
public class ImportCommand implements Callable<Integer> {

    @Option(names = {"--workspace", "-w"})
    Path workspacePath;

    @Parameters(description = "Sources to import data from")
    Set<String> sources;

    @Override
    public Integer call() {
        if (sources == null || sources.isEmpty()) {
            throw new IllegalArgumentException("No sources specified");
        }

        if (workspacePath == null) {
            workspacePath = Paths.get("");
        }
        workspacePath = workspacePath.normalize().toAbsolutePath();
        if (!Files.exists(workspacePath)) {
            throw new IllegalArgumentException("Workspace directory %s does not exist".formatted(workspacePath));
        }
        if (!Files.isDirectory(workspacePath)) {
            throw new IllegalArgumentException("Workspace path %s is not a directory".formatted(workspacePath));
        }

        final var importTasks = new ArrayList<ImportTask>();
        for (final var importer : ServiceLoader.load(Importer.class)) {
            if (!sources.contains(importer.source().name())) {
                continue;
            }

            final var database = DatabaseImpl.forSource(workspacePath, importer.source());
            importer.init(database);
            importTasks.add(new ImportTask(importer));
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

        private final Importer importer;

        public ImportTask(final Importer importer) {
            this.importer = importer;
        }

        @Override
        public void run() {
            try (var ignoredMdcSource = MDC.putCloseable("source", importer.source().name())) {
                importer.runImport();
            } catch (Exception e) {
                throw new RuntimeException("Importer for source %s failed".formatted(
                        importer.source().name()), e);
            }
        }

    }

}

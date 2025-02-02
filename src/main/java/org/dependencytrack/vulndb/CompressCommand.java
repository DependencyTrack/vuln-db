package org.dependencytrack.vulndb;

import com.github.luben.zstd.ZstdOutputStream;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Command(name = "compress", description = "Compress a database for distribution.")
public class CompressCommand implements Runnable {

    @Parameters
    private Path inputFilePath;

    @Option(names = "-output")
    private Path outputFilePath;

    @Option(names = "-level", defaultValue = "5")
    private int compressionLevel;

    @Override
    public void run() {
        try (final var fileOutputStream = Files.newOutputStream(outputFilePath);
             final var bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
             final var zstdOutputStream = new ZstdOutputStream(bufferedOutputStream, compressionLevel)) {
            Files.copy(inputFilePath, zstdOutputStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

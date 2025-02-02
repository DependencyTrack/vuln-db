package org.dependencytrack.vulndb;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
        name = "vuln-db",
        version = "1.0.0-SNAPSHOT",
        mixinStandardHelpOptions = true,
        subcommands = {
                CompressCommand.class,
                ImportCommand.class,
                MergeCommand.class,
                ScanCommand.class})
public class Application {

    public static void main(final String[] args) {
        System.exit(new CommandLine(new Application()).execute(args));
    }

}

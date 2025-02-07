package org.dependencytrack.vulndb.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
        name = "vuln-db",
        version = "1.0.0-SNAPSHOT",
        mixinStandardHelpOptions = true,
        subcommands = {
                ImportCommand.class,
                MergeCommand.class,
                ScanCommand.class})
public class MainCommand {

    public static void main(final String[] args) {
        System.exit(new CommandLine(new MainCommand()).execute(args));
    }

}

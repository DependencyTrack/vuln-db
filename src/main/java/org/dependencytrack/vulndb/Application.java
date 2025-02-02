package org.dependencytrack.vulndb;

import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.util.concurrent.Callable;

@Command(
        name = "vuln-db",
        version = "1.0.0-SNAPSHOT",
        mixinStandardHelpOptions = true,
        subcommands = {
                CompressCommand.class,
                ImportCommand.class,
                MergeCommand.class})
public class Application implements Callable<Integer> {

    public static void main(final String[] args) {
        System.exit(new CommandLine(new Application()).execute(args));
    }

    @Override
    public Integer call() {
        return 0;
    }

}

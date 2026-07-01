import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.util.task.TaskMonitor;

public class ExportGzf extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("Usage: ExportGzf.java <output.gzf>");
            return;
        }
        File outputFile = new File(args[0]);
        DomainFile df = currentProgram.getDomainFile();
        df.packFile(outputFile, monitor);
        println("Exported archive: " + outputFile.getAbsolutePath());
    }
}

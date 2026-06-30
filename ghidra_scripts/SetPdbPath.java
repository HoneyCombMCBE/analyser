import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;

public class SetPdbPath extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("Usage: SetPdbPath.java <pdb_file_path>");
            return;
        }
        File pdbFile = new File(args[0]);
        if (!pdbFile.exists()) {
            println("PDB file not found: " + pdbFile.getAbsolutePath());
            return;
        }
        PdbUniversalAnalyzer.setPdbFileOption(currentProgram, pdbFile);
        println("Set PDB path: " + pdbFile.getAbsolutePath());
    }
}

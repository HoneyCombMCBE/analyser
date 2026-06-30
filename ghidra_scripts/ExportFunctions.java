import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.util.exception.*;

public class ExportFunctions extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("Usage: ExportFunctions.java <output.json>");
            return;
        }
        String outputPath = args[0];

        FunctionManager fm = currentProgram.getFunctionManager();
        Memory memory = currentProgram.getMemory();

        StringBuilder json = new StringBuilder(1024 * 1024);
        json.append("{\n");
        json.append("  \"binary\": \"").append(escape(currentProgram.getName())).append("\",\n");
        json.append("  \"imageBase\": \"0x").append(Long.toHexString(currentProgram.getImageBase().getOffset())).append("\",\n");
        json.append("  \"functions\": [\n");

        boolean first = true;
        int total = 0;

        for (Function func : fm.getFunctions(true)) {
            if (func.isThunk()) continue;
            if (func.isExternal()) continue;

            if (!first) {
                json.append(",\n");
            }
            first = false;

            json.append("    {");
            json.append("\"name\": \"").append(escape(func.getName())).append("\",");

            Address entry = func.getEntryPoint();
            json.append("\"address\": \"0x").append(Long.toHexString(entry.getOffset())).append("\",");

            AddressSetView body = func.getBody();
            long size = body.getNumAddresses();
            json.append("\"size\": ").append(size).append(",");

            StringBuilder hex = new StringBuilder();
            if (size > 0) {
                byte[] buf = new byte[(int) Math.min(size, 1_000_000)];
                try {
                    int n = memory.getBytes(entry, buf);
                    for (int i = 0; i < n; i++) {
                        hex.append(String.format("%02x", buf[i] & 0xFF));
                    }
                } catch (MemoryAccessException e) {
                    hex.append("ERROR");
                }
            }
            json.append("\"bytes\": \"").append(hex).append("\"");

            json.append("}");
            total++;
        }

        json.append("\n  ],\n");
        json.append("  \"total\": ").append(total).append("\n");
        json.append("}\n");

        try (PrintWriter pw = new PrintWriter(new File(outputPath))) {
            pw.print(json.toString());
        }

        println("Exported " + total + " functions to " + outputPath);
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}

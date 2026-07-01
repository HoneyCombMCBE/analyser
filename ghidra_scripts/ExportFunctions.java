import java.io.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.OperandType;
import ghidra.util.exception.*;

public class ExportFunctions extends GhidraScript {

    private static final int SIG_MAX_BYTES = 64;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("Usage: ExportFunctions.java <output.json>");
            return;
        }
        String outputPath = args[0];

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
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
            json.append("\"bytes\": \"").append(hex).append("\",");

            String sig = buildSignature(listing, memory, func);
            json.append("\"signature\": \"").append(sig).append("\"");

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

    private String buildSignature(Listing listing, Memory memory, Function func) {
        Address entry = func.getEntryPoint();
        AddressSetView body = func.getBody();
        StringBuilder sig = new StringBuilder();
        int byteCount = 0;

        InstructionIterator iter = listing.getInstructions(body, true);
        while (iter.hasNext() && byteCount < SIG_MAX_BYTES) {
            Instruction insn = iter.next();
            byte[] insnBytes;
            try {
                int len = insn.getLength();
                insnBytes = new byte[len];
                memory.getBytes(insn.getAddress(), insnBytes);
            } catch (MemoryAccessException e) {
                break;
            }

            boolean[] mask = new boolean[insnBytes.length];
            Arrays.fill(mask, true);

            int numOps = insn.getNumOperands();
            for (int op = 0; op < numOps; op++) {
                int opType = insn.getOperandType(op);
                boolean isAddr = (opType & OperandType.ADDRESS) != 0;
                boolean isDynamic = (opType & OperandType.DYNAMIC) != 0;
                if (!isAddr && !isDynamic) continue;

                List<Object> opObjects = insn.getDefaultOperandRepresentationList(op);
                for (Object obj : opObjects) {
                    if (obj instanceof Address) {
                        wildcardOperandBytes(insn, insnBytes, mask);
                        break;
                    }
                }
            }

            for (int i = 0; i < insnBytes.length && byteCount < SIG_MAX_BYTES; i++) {
                if (sig.length() > 0) sig.append(' ');
                if (mask[i]) {
                    sig.append(String.format("%02X", insnBytes[i] & 0xFF));
                } else {
                    sig.append('?');
                }
                byteCount++;
            }
        }

        return sig.toString();
    }

    private void wildcardOperandBytes(Instruction insn, byte[] insnBytes, boolean[] mask) {
        int prefixLen = insn.getPrototype().getPrefixLength();
        int opLen = insn.getPrototype().getOpCodeLength();
        int start = prefixLen + opLen;
        for (int i = start; i < mask.length; i++) {
            mask[i] = false;
        }
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}

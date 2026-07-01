#!/usr/bin/env python3
"""Parse BinDiff results and generate wildcarded function signatures.

Usage:
    generate_signatures.py <bindiff.db> <bds_functions.json> <edu_functions.json> <threshold> <output.json>
"""

import json
import os
import sqlite3
import sys


def load_functions(path):
    """Load functions.json and index by hex address."""
    with open(path) as f:
        data = json.load(f)
    funcs = {}
    for func in data["functions"]:
        addr = int(func["address"], 16)
        funcs[addr] = func
    return funcs


def parse_class_name(symbol):
    """Split 'Class::method' into (classname, methodname).

    Handles nested classes like 'Outer::Inner::method'.
    """
    if "::" not in symbol:
        return "", symbol
    parts = symbol.rsplit("::", 1)
    return parts[0], parts[1]


def main():
    if len(sys.argv) != 6:
        print(f"Usage: {sys.argv[0]} <bindiff.db> <bds.json> <edu.json> <threshold> <output.json>")
        sys.exit(1)

    bindiff_db = sys.argv[1]
    bds_json = sys.argv[2]
    edu_json = sys.argv[3]
    threshold = float(sys.argv[4])
    output_path = sys.argv[5]

    bds_funcs = load_functions(bds_json)
    edu_funcs = load_functions(edu_json)

    conn = sqlite3.connect(bindiff_db)
    cursor = conn.execute(
        "SELECT address1, name1, address2, name2, similarity, confidence "
        "FROM function WHERE similarity >= ? ORDER BY similarity DESC",
        (threshold,),
    )

    functions = []
    seen_edu_addrs = set()

    for addr1, name1, addr2, name2, similarity, confidence in cursor:
        addr1 = int(addr1)
        addr2 = int(addr2)

        if addr2 in seen_edu_addrs:
            continue

        bds_name = name1 or ""
        if not bds_name or bds_name.startswith("FUN_") or bds_name.startswith("thunk_FUN_"):
            continue

        edu_func = edu_funcs.get(addr2)
        if not edu_func:
            continue

        signature = edu_func.get("signature", "")
        if not signature:
            continue

        seen_edu_addrs.add(addr2)

        classname, funcname = parse_class_name(bds_name)

        entry = {
            "symbol": bds_name,
            "classname": classname,
            "classfuncname": funcname,
            "demangledname": bds_name,
            "signature": signature,
            "isclass": 1 if classname else 0,
            "isvirtual": 0,
            "voffset": -1,
            "similarity": round(similarity, 4),
            "confidence": round(confidence, 4),
            "edu_address": edu_func["address"],
            "edu_size": edu_func["size"],
        }
        functions.append(entry)

    conn.close()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    output = {
        "bds_source": bds_json,
        "edu_source": edu_json,
        "threshold": threshold,
        "matched": len(functions),
        "functions": functions,
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Generated {len(functions)} signatures (threshold={threshold})")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import sys
from pathlib import Path

def merge_files(output_file, input_files):
    with open(output_file, "w", encoding="utf-8") as out:
        for rel_path in input_files:
            path = Path(rel_path)

            out.write(f"\n{'=' * 80}\n")
            out.write(f"START OF FILE: {rel_path}\n")
            out.write(f"{'=' * 80}\n\n")

            if not path.exists():
                out.write(f"[WARNING] File not found: {rel_path}\n")
            elif not path.is_file():
                out.write(f"[WARNING] Not a file: {rel_path}\n")
            else:
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        out.write(f.read())
                except Exception as e:
                    out.write(f"[ERROR] Could not read file: {e}\n")

            out.write(f"\n\n{'=' * 80}\n")
            out.write(f"END OF FILE: {rel_path}\n")
            out.write(f"{'=' * 80}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python merge_files.py <relative_path1> <relative_path2> ...")
        sys.exit(1)

    output = "merged.txt"
    inputs = sys.argv[1:]

    merge_files(output, inputs)
    print(f"✅ Merged {len(inputs)} files into '{output}'")

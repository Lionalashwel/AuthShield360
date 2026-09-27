#!/usr/bin/env python3
"""Write a real ZIP archive from a newline-delimited relative-path manifest.
Usage: python _zippack.py <manifest> <output.zip>
"""
import sys, zipfile

manifest = [ln.strip() for ln in open(sys.argv[1], encoding='utf-8') if ln.strip()]
with zipfile.ZipFile(sys.argv[2], 'w', zipfile.ZIP_DEFLATED) as z:
    for rel in manifest:
        z.write(rel, rel)
print(f'zip wrote {len(manifest)} entries')
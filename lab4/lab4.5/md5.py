#!/usr/bin/env python3
import hashlib
import argparse
import sys

def md5_of_string(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def md5_of_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    parser = argparse.ArgumentParser(
        description="Tính MD5 của một chuỗi hoặc file"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--string", help="chuỗi cần băm MD5")
    group.add_argument("-f", "--file",   help="đường dẫn file cần băm MD5")
    args = parser.parse_args()

    if args.string is not None:
        print(md5_of_string(args.string))
    else:
        print(md5_of_file(args.file))

if __name__ == "__main__":
    main()

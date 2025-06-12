#!/usr/bin/env python3
import argparse, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def main():
    p = argparse.ArgumentParser(description="RSA decrypt with public key → Base64")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-s", "--string", help="Base64-encoded input")
    g.add_argument("-f", "--file",   help="File with Base64-encoded input")
    p.add_argument("-k", "--key",    required=True, help="Public key PEM")
    args = p.parse_args()

    raw = base64.b64decode(args.string) if args.string \
          else base64.b64decode(open(args.file, "rb").read())
    pub = serialization.load_pem_public_key(
        open(args.key, "rb").read(),
        backend=default_backend()
    )
    e, n = pub.public_numbers().e, pub.public_numbers().n
    k = (n.bit_length() + 7) // 8
    out = bytearray()
    for i in range(0, len(raw), k):
        c = int.from_bytes(raw[i : i + k], "big")
        m = pow(c, e, n)
        out += m.to_bytes(k - 1, "big").lstrip(b"\x00")
    print(out.decode("utf-8", errors="ignore"))

if __name__ == "__main__":
    main()

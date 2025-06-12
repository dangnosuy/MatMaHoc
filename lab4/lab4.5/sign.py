#!/usr/bin/env python3
import argparse, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def main():
    p = argparse.ArgumentParser(description="RSA “encrypt” with private key → Base64")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-s", "--string", help="Chuỗi đầu vào")
    g.add_argument("-f", "--file",   help="File đầu vào")
    p.add_argument("-k", "--key",    required=True, help="File private key PEM")
    args = p.parse_args()

    data = args.string.encode("utf-8") if args.string else open(args.file, "rb").read()
    priv = serialization.load_pem_private_key(
        open(args.key, "rb").read(),
        password=None,
        backend=default_backend()
    )

    # raw RSA: c = m^d mod n
    nums = priv.private_numbers()
    d, n = nums.d, nums.public_numbers.n
    k = (n.bit_length() + 7) // 8
    out = bytearray()
    for i in range(0, len(data), k-1):
        block = data[i : i + (k - 1)]
        m = int.from_bytes(block, "big")
        c = pow(m, d, n)
        out += c.to_bytes(k, "big")

    print(base64.b64encode(bytes(out)).decode("ascii"))

if __name__ == "__main__":
    main()

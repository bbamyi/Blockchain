#!/usr/bin/env python3
import hashlib

DIFFICULTY_BITS = 24  # from the pass-off site

def int_to_big_endian(n: int) -> bytes: # encode non neg int as big endian
    if n < 0:
        raise ValueError("nonce must be non-negative")
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")

def mine_block(prev_hash_hex: str, quote: str, difficulty_bits: int):
   # return nonce and block hash hex
    prev_hash = bytes.fromhex(prev_hash_hex)
    quote_bytes = quote.encode("ascii")

    # for difficulty 24 just check first 3 bytes of the digest
    zero_bytes = difficulty_bits // 8  # assume difficulty_bits is multiple of 8
    target_prefix = b"\x00" * zero_bytes

    nonce = 0
    while True:
        nonce_bytes = int_to_big_endian(nonce)
        digest = hashlib.sha256(prev_hash + nonce_bytes + quote_bytes).digest()
        if digest.startswith(target_prefix):
            return nonce, digest.hex()
        nonce += 1

if __name__ == "__main__":
    
    prev_hash_hex = input("previous block hash (hex): ").strip()
    quote = input("put quote here: ").strip()

    nonce, block_hash_hex = mine_block(prev_hash_hex, quote, DIFFICULTY_BITS)

    print("\nfound solution!")
    print("nonce:", nonce)
    print("block hash:", block_hash_hex) 

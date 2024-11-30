#!/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import sys
import argparse

leave_padding = False
filename = "/dev/stdout"
key_sizes = [ 128, 192, 256 ]
valid_modes = [ 'cbc', 'ctr', 'ecb' ]

def check_key(key):
    # Check key length
    if key == None:
        raise ValueError("Expected value in 'aem_key' environment variable.")

    # Convert hex key into byte object then get length
    bkey = bytes.fromhex(key)
    key_size = len(bkey) * 8

    if key_size not in key_sizes:
        raise ValueError(f"Key must be ${key_sizes} long. Key given is {len(key) * 4} bits.")
    return bkey

def decrypt_message(message, key, mode, extra_bits):
    if mode == "cbc":
        cipher_mode = modes.CBC(extra_bits)
    elif mode == "ctr":
        cipher_mode = modes.CTR(extra_bits)
    elif mode == "ecb":
        cipher_mode = modes.ECB()
    else:
        raise ValueError(f"Invalid mode must be one of the following: {valid_modes}")

    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(message) + decryptor.finalize()

    if (mode == 'cbc' or mode == 'ecb') and not leave_padding:
       # Removed padding
       unpadder = padding.PKCS7(128).unpadder()
       return unpadder.update(decrypted) + unpadder.finalize()

    return decrypted 

def main(mode, extra_bits):
    key = check_key(os.getenv('aem_key'))
    if sys.stdin.isatty(): 
        print("No input detected")
        return
    else:
        message = sys.stdin.read()

    bmessage = bytes.fromhex(message) 

    dec = decrypt_message(bmessage, key, mode, extra_bits)
    with open(filename, 'wb') as f:
        if output_type == "hex":
            f.write(dec.hex().encode())
        else: 
            f.write(repr(dec).encode())
    print("\n")


if __name__ == "__main__":
    global output_type

    extra_bits = ""
    parser = argparse.ArgumentParser(description="This script encrypts input using AES.")
    parser.add_argument(
            '-m', '--mode', default=valid_modes[0], choices=valid_modes)
    parser.add_argument(
            '-i', '--iv', default="", help="Expected if using cbc mode.")
    parser.add_argument(
            '-n', '--nonce', default="", help="Expected if using ctr mode.")
    parser.add_argument(
            '-l', '--leave-padding', action="store_true", help="Will show padding when decrypted if using cbc or ecb mode.")
    parser.add_argument(
            '-o', '--output', default="hex", choices=["hex","binary"])
    args = parser.parse_args()
    output_type = args.output

    if args.leave_padding:
        leave_padding = True

    if args.mode == "cbc":
        if args.iv == "":
            print("Must provide 'iv' to decrypt in CBC mode")
            sys.exit(1)

        extra_bits = bytes.fromhex(args.iv)

    elif args.mode == "ctr": 
        if args.nonce == "":
            print("Must provide 'nonce' to decrypt in CTR mode")
            sys.exit(1)

        extra_bits = bytes.fromhex(args.nonce)

    try:
        main(args.mode, extra_bits)
    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)

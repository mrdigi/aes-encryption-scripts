#!/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import sys
import argparse

key_sizes = [ 128, 192, 256 ]
valid_modes = [ 'cbc', 'ctr', 'ecb' ]
filename = "/dev/stdout"
summary = {}

def check_key():
    key = os.getenv(key_variable)
    # Check key length
    if key == None:
        raise ValueError(f"No key value found in '{key_variable}' environment variable.")

    # Convert hex key into byte object then get length
    bkey = bytes.fromhex(key)
    key_size = len(bkey) * 8
    summary['key_size'] = key_size
    summary['variable'] = key_variable

    if key_size not in key_sizes:
        raise ValueError(f"Key must be ${key_sizes} long. Key given is {len(key) * 4} bits.")

    return bkey

def encrypt_message(message, key, mode, iv=os.urandom(16)):
    summary['mode'] = mode
    summary['input_length'] = len(message)
    if mode == "cbc":
        cipher_mode = modes.CBC(iv)
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message) + padder.finalize()
        message_to_encrypt = padded_message
        summary['iv'] = iv.hex()
    elif mode == "ctr":
        cipher_mode = modes.CTR(iv)
        message_to_encrypt = message
        summary['nounce'] = iv.hex()
    elif mode == "ecb":
        cipher_mode = modes.ECB()
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message) + padder.finalize()
        message_to_encrypt = padded_message
    else:
        raise ValueError("Invalid mode, must use 'CBC' or 'CTR'")

    summary['output_length'] = len(message_to_encrypt)


    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message_to_encrypt) + encryptor.finalize()

    return ciphertext


def main(mode):
    global filename 
    key = check_key()

    if sys.stdin.isatty():
        print("No input detected")
        return
    else:
        message = sys.stdin.buffer.read() 

    ciphertext = encrypt_message(message, key, mode)

    if not summary_disabled: 
        print(summary)

    with open(filename, 'wb') as f:
        if output_type == "hex":
            f.write(ciphertext.hex().encode())
        else:
            f.write(ciphertext)

    print("\n")


if __name__ == "__main__":
    global key_variable
    global output_type 
    global summary_disabled

    parser = argparse.ArgumentParser(description="This script encrypts input using AES.")
    parser.add_argument('-m', '--mode', default=valid_modes[0], choices=valid_modes)
    parser.add_argument('-k', '--key', default='aem_key', help="Environment variable to use for key.")
    parser.add_argument('-o', '--output', default="hex", choices=["hex","binary"])
    parser.add_argument('-f', '--file', help="File to write to instead of stdout")
    parser.add_argument('-q', '--quiet', action="store_true", help="Disable summary")
    parser.add_argument('-c', '--check-key', action="store_true", help="Checks key status")
    args = parser.parse_args()

    key_variable = args.key
    if args.check_key:
        check_key()
        print(summary)
        sys.exit(1)

    output_type = args.output
    summary_disabled = args.quiet

    if args.file:
        # Default to working directory if path is missing
        if '/' not in args.file:
            filename = f"{os.getcwd()}/{args.file}"
        else:
            file_path = '/'.join(args.file.split('/')[0:-1])
            if os.path.exists(file_path):
                filename = args.file
            else:
                print(f"ERROR: File path '{file_path}' doesnn't exist\n")
                sys.exit(1)
             
    try:
        main(args.mode)
    except Exception as e:
        print(f"ERROR: {str(e)}\n")
        sys.exit(1)

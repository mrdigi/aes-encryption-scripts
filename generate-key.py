#!/bin/env python3
from datetime import datetime
from scipy.stats import entropy
import numpy as np
import re
import sys
import time
import argparse
import getpass
import hashlib


def gauge_entropy(random_bytes):
    byte_values = np.frombuffer(random_bytes, dtype=np.uint8)
    histogram = np.bincount(byte_values, minlength=32)
    ent = entropy(histogram, base=2)
    print(f"Entropy: {ent}")

def delay_round(delay):
    start_time = datetime.now().timestamp()
    while (datetime.now().timestamp() - start_time) < delay:
        pass


def shuffle_bytes(inbytes, num, rounds):
    outbytes = list(inbytes)
    for a,b in zip(range(0,16,2), range(31,16,-2)):
        outbytes[a] = inbytes[b]
        outbytes[b] = inbytes[a]

    for i in range(1, 32, num+1): 
        byte = outbytes[i]
        if byte >= 189:
            outbytes[i] = (byte + (rounds * num)) % 255
        else:
            outbytes[i] = (outbytes[i] + rounds)  % 255

    if num < rounds:
        outbytes = shuffle_bytes(outbytes, num+1, rounds)
    return outbytes 


def username_mangle(username, last_feed):
    # This step remains optional, but in certain environments it may be deligient to hide
    # username information when including it into a hash.

    # Pad or cut username to 32 characters 
    if len(username) < 32:
        username = bytes(username.encode() + bytes([189])*(32-len(username)))
    else:
        username = bytes(username[0:32].encode())
    
    # Shuffle bytes 
    outbytes = shuffle_bytes(username, 0, 32)

    # Xor chunks
    return bytes([a ^ b for a,b in zip(outbytes, last_feed)]).hex()


def main(size, rounds, passkey, delay=0, inject_marker="", last_feed="", quiet=False, verbose=False):
    summary = {}
    r, injections = 0, 0
    sha256_hash = hashlib.sha256()

    # Last_feed acts as a salt, but is modified during certain rounds.  This initiates the 
    # initial 'salt' if not provided by user.  Default value here was obtained from /dev/random 
    # and has no special meaning or properties.
    if not last_feed:
        last_feed = "fd4a1d671c60d418cc1cf43e25f42f12d87b78003e00e39a466b696f74cce6f5".encode('utf-8')

    user_bytes = username_mangle(getpass.getuser(), last_feed)
    user_hash = hashlib.sha256(user_bytes.encode('utf-8')).digest()
    passkey_hash = hashlib.sha256(passkey.encode('utf-8')).digest()

    # XOR initial hashes
    initial_hash = bytes([a ^ b for a,b in zip(user_hash, passkey_hash)])
    if not inject_marker:
        inject_marker = initial_hash.hex()[0:3]
    sha256_hash.update(initial_hash)

    feeds = []
    start_time = datetime.now().timestamp()
    while r < rounds: 
        if r % 2 == 0: 
            feed = sha256_hash.hexdigest()[0:32]
        else:
            feed = sha256_hash.hexdigest()[32:64]
            
        if inject_marker in feed:
            feed = str(bytes([a ^ b for a,b in zip(user_hash, last_feed)]))
            injections += 1

        last_feed = feed.encode()
        sha256_hash.update(feed.encode())

        if verbose:
            print(f"Round {r}: {sha256_hash.hexdigest()}")

        # If delay was given we wait here
        if delay > 0:
            delay_round(delay*0.001)
        r += 1

    # Get key size in bytes
    key_size = int(size/4)
    elapsed_time = datetime.now().timestamp()-start_time
    summary['rounds'] = rounds
    summary['key_size'] = size 
    summary['injection_marker'] = inject_marker
    summary['injections'] = injections 
    summary['elapsed_time'] = f"{round(elapsed_time*1000,3)} millseconds"

    if not quiet:
        print(summary)
    return sha256_hash.hexdigest()[0:key_size]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="This script encrypts input using AES.")
    parser.add_argument(
            '-s', '--size', default=128, type=int, choices=[128,256],help="Key size to generate.")
    parser.add_argument(
            '-r', '--rounds', default="2k", type=str, help="How many rounds of hashing")
    parser.add_argument(
            '-d', '--delay', default=0, type=int, help="Delay in ms before each hash")
    parser.add_argument(
            '-q', '--quiet',action="store_true", default=False)
    parser.add_argument(
            '-v', '--verbose',action="store_true")
    parser.add_argument(
            '-i', '--inject_marker',type=str, default="", help="Injects additional information into hash")
    args = parser.parse_args()

    # Parse number of rounds
    rounds = 0
    if args.rounds.endswith('k'):
        number = args.rounds.split('k')[0]
        rounds = int(number)*10**3
    elif args.rounds.endswith('m'):
        number = args.rounds.split('m')[0]
        rounds = int(number)*10**6
    else:
        rounds = int(args.rounds)

    passkey = getpass.getpass("Enter passkey: ")
    passkey2 = getpass.getpass("Re-enter passkey: ")

    if passkey != passkey2:
        print("\nERROR: passkeys provided did not match.\n")
        sys.exit(1)

    key_hash = main(
            args.size, 
            rounds, 
            passkey, 
            delay=args.delay,
            inject_marker=args.inject_marker, 
            quiet=args.quiet,
            verbose=args.verbose)    

    if args.quiet:
        print(key_hash)
    else:
        print(f"Generated key: {key_hash}")

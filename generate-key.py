#!/bin/env python3
from datetime import datetime
import argparse
import getpass
import hashlib

def main(size, rounds, passkey, inject_marker="", verbose=False):
    last_feed = "g0blins!"
    r, injections = 0, 0
    user = getpass.getuser()
    summary = {}
    sha256_hash = hashlib.sha256()
    sha256_hash.update(passkey.encode())

    feeds = []
    start_time = datetime.now().timestamp()
    while r < rounds: 
        if r % 2 == 0: 
            feed = sha256_hash.hexdigest()[0:32]
        else:
            feed = sha256_hash.hexdigest()[32:64]
            
        if inject_marker in feed:
            feed = f"{feed}:{user}:{last_feed}"
            injections += 1
        last_feed = feed
        sha256_hash.update(feed.encode())
        if verbose:
            print(f"Round {round}: {sha256_hash.hexdigest()}")
        r += 1

    # Get key size in bytes
    key_size = int(size/4)
    elapsed_time = datetime.now().timestamp()-start_time
    summary['rounds'] = rounds
    summary['key_size'] = size 
    summary['injections'] = injections 
    summary['elapsed_time'] = f"{round(elapsed_time*1000,3)} millseconds"
    print(summary)
    return sha256_hash.hexdigest()[0:key_size]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="This script encrypts input using AES.")
    parser.add_argument(
            '-s', '--size', default=128, type=int, choices=[128,256],help="Key size to generate.")
    parser.add_argument(
            '-r', '--rounds', default=1024, type=int, help="How many rounds of hashing")
    parser.add_argument(
            '-v', '--verbose',action="store_true")
    parser.add_argument(
            '-i', '--inject_marker',type=str, default="ae", help="Injects additional information into hash")
    args = parser.parse_args()

    passkey = getpass.getpass("Enter passkey: ")

    key_hash = main(
            args.size, 
            args.rounds, 
            passkey, 
            inject_marker=args.inject_marker, 
            verbose=args.verbose)    

    print(f"Generated key: {key_hash}")

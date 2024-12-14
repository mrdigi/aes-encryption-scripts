# aes-encryption-scripts
A set of scripts that allow encrypting and decrypting data in AES modes ecb, cbc, and ctr.

# generate-key.py
This is an exerimental script to generate a key based on a password, much like pbkdf/2.  Instead of a salt I use the username of the person running the script, and I added the idea of injection markers. 

An injection marker is just a pattern that matches the hash in a current round, when matched this will add the initial hash with the username, along with the previous hash from last round.  For Example:

```generate-key.py -s 128 -r 500k -i aef```

The above will return a 128-bit key after a 500,000 rounds of hashing.  During the hash rounds if the hash ends up having 'aef' in the returned hash, the injection of the initial starting hash along with the last hash is used instead of what normally would've been hashed.  In this case 3,730 injections were added during the rounds. 

**note**:  While this script in practice should be fairly secure, it's just experimental and don't recommend it being used for anything important.

# aes-encrypt.py


# aes-decrypt.py

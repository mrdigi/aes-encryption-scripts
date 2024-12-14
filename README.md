# AES-encryption-scripts
A set of scripts that allow encrypting and decrypting data in AES modes ecb, cbc, and ctr.

## generate-key.py
This is an exerimental script to generate a key based on a password, much like pbkdf/2.  Instead of a salt I use the username of the person running the script, and I added the idea of injection markers. 

An injection marker is just a pattern that matches the hash in a current round, when matched this will add the initial hash with the username, along with the previous hash from last round.  For Example:

```generate-key.py -s 128 -r 500k -i aef```

The above will return a 128-bit key after a 500,000 rounds of hashing.  During the hash rounds if the hash ends up having 'aef' in the returned hash, the injection of the initial starting hash along with the last hash is used instead of what normally would've been hashed.  In this case 3,730 injections were added during the rounds. In a way this creates branching within the rounds of hashing.

**note**:  While this script in practice should be fairly secure, it's just experimental and don't recommend it being used for anything important.

## aes-encrypt.py
A script that supports AES encryption with modes ECB, CBC, and CTR.  

### General:
aes-encrypt.py needs at the very least a key, one like generate-key.py can provide, but see the warning.  It takes it's input via stdin like so:

```echo "Hello World!" | aes-encrypt.py -k MY_AES_KEY```

**Note**: The argument -k takes an environment variable to help avoid leaking keys

The output below has a summary in the {} braces, which can be turned off using the '-q' flag.  Below that is the encrypted value of "Hello World!" but dumped out as hex as not to 
interrupt the flow of the terminal.  You can however over-ride the default with '--output binary'.  This is only recommended however if you choose to save the results into a file
with the '-f <filename>' argument.
```
{'key_size': 128, 'variable': 'AES_KEY', 'mode': 'cbc', 'input_length': 12, 'iv': 'd38e4fbe67976f47715e50ee4d57b8ba', 'output_length': 16}
4265b98ad129517b183f26955070ba16
```
**Note**:  The IV or Nonce is currently choosen for you at random and printed in the summary.  There is currently no way to specify the IV or Nonce which are needed, so if you want to 
decrypt later, pay close attentioned to the summary output.

## aes-decrypt.py

This is the inverse of the aes-encrypt.py script.  

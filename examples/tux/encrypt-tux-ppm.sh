#!/bin/bash

mkdir encrypted 2>/dev/null
if [ -z $aem_key ]; then
    AES_KEY=$(head -c 32 /dev/random | xxd -p)
    export aem_key=${AES_KEY}
fi

# Seperate image file header and body
tuxHeader=$(head -n 3 tux.ppm | xxd -p)
tuxBody=$(tail -n +4 tux.ppm)

# Encrypt in available modes
ecb_encrypted=$(echo $tuxBody | ../../aes-encrypt.py -q --mode ecb)
cbc_encrypted=$(echo $tuxBody | ../../aes-encrypt.py -q --mode cbc)
ctr_encrypted=$(echo $tuxBody | ../../aes-encrypt.py -q --mode ctr)

#output to files
echo ${tuxHeader}${ecb_encrypted} | xxd -r -p > encrypted/tux.ecb
echo ${tuxHeader}${cbc_encrypted} | xxd -r -p > encrypted/tux.cbc
echo ${tuxHeader}${ctr_encrypted} | xxd -r -p > encrypted/tux.ctr

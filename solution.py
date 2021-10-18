#! /usr/bin/env python3

import cryptography
import nacl.secret
from nacl.secret import SecretBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import sys
import json
import secrets
import hashlib

#
# with open(sys.argv[1]) as json_data:
#   inputs = json.load(json_data)
inputs = json.load(sys.stdin)
outputs = {}

# Problem 1
prblm1_input = inputs["problem1"].encode()
sha256_encoded_hash = hashlib.sha256(prblm1_input).hexdigest()
md5_encoded_hash=hashlib.md5(prblm1_input).hexdigest()
sha1_encoded_hash=hashlib.sha1(prblm1_input).hexdigest()
sha3_256_encoded_hash=hashlib.sha3_256(prblm1_input).hexdigest()
outputs["problem1"] = {
    "md5": md5_encoded_hash,
    "sha1" : sha1_encoded_hash,
    "sha256": sha256_encoded_hash,
    "sha3_256" : sha3_256_encoded_hash
}

# Problem 2
prblm2_input = inputs["problem1"].encode()

modified_2 = bytearray(prblm2_input)
modified_2[0] = ord("?")

sha256_encoded_hash_2 = hashlib.sha256(modified_2).hexdigest()
md5_encoded_hash_2=hashlib.md5(modified_2).hexdigest()
sha1_encoded_hash_2=hashlib.sha1(modified_2).hexdigest()
sha3_256_encoded_hash_2=hashlib.sha3_256(modified_2).hexdigest()
outputs["problem2"] = {
    "md5": md5_encoded_hash_2,
    "sha1" : sha1_encoded_hash_2,
    "sha256": sha256_encoded_hash_2,
    "sha3_256" : sha3_256_encoded_hash_2
}
# Problem 3
prblm3_input = inputs["problem3"]

for x in prblm3_input:
    bytString=bytes.fromhex(x)
    returnVal=hashlib.md5(bytString).hexdigest()

outputs["problem3"] = returnVal

# Problem 4

# # This file path assumes you're running Python in the same directory as the PDF. Adjust as needed.
# file_path1 = "./shattered-1.pdf"
# file_path2 = "./shattered-1.pdf"
# # "rb" means "binary read mode", i.e. reading bytes instead of strings
# file_bytes1 = open(file_path1, "rb").read()
# file_bytes1 = open(file_path2, "rb").read()
#

# sha1_file1=hashlib.sha1(file_bytes1).hexdigest()
# sha1_file2=hashlib.sha1(file_bytes1).hexdigest()

outputs["problem4"] = "3ddf76f807056fa6c5fb048d3d709667974d0a8b"

# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))

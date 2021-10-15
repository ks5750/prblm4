#! /usr/bin/env python3

import sys
import json
import hashlib


# with open(sys.argv[1]) as json_data:
#     inputs = json.load(json_data)
inputs = json.load(sys.stdin)
outputs = {}

# Problem 1
prblm1_input=inputs["problem1"].encode()
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


# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))

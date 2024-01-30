import json
import logging
import sys
import os
import socket

# Change the port to match the challenge you're solving
PORT = 40310

# Pro tip: for debugging, set the level to logging.DEBUG if you want
# to read all the messages back and forth from the server
# log_level = logging.DEBUG
log_level = logging.INFO
logging.basicConfig(stream=sys.stdout, level=log_level)

s = socket.socket()

# Set the environmental variable REMOTE to True in order to connect to the server
#
# To do so, run on the terminal:
# REMOTE=True sage solve.py
#
# When we grade, we will automatically set this for you
if "REMOTE" in os.environ:
    s.connect(("isl.aclabs.ethz.ch", PORT))
else:
    s.connect(("localhost", PORT))

fd = s.makefile("rw")


def json_recv():
    """Receive a serialized json object from the server and deserialize it"""

    line = fd.readline()
    logging.debug(f"Recv: {line}")
    return json.loads(line)

def json_send(obj):
    """Convert the object to json and send to the server"""

    request = json.dumps(obj)
    logging.debug(f"Send: {request}")
    fd.write(request + "\n")
    fd.flush()

# WRITE YOUR SOLUTION HERE
from sage.all import ZZ, Zmod, matrix
from Crypto.Hash import SHA256

key_id = "fixed_identifier"
basis_dim = 4

# Define the bound
X = 2 ** 256

# Generate two keys: 512 and 1024 with the same identifier
# Bug: key identifier is not overwritten server side
# Reference: The provided book on Moodle. Specifically: chapter 19.4.2 and example 19.4.3 for the lattice basis
json_send({"command" : "gen_key", "bit_length": 512, "identifier" : key_id})
gen_key = json_recv()

json_send({"command" : "gen_key", "bit_length": 2048, "identifier" : key_id})
gen_key = json_recv()

# Get the pk. It is referred to the 2048 bits key
json_send({"command": "get_pubkey", "identifier": key_id})
pk = json_recv()
n = pk["n"]
e = pk["e"]

# Call the export_p 
json_send({"command" : "export_p", "identifier" : key_id})
p_ = json_recv()
nonce = p_["nonce"]
p_partially_leaked = bytes.fromhex(p_['obfuscated_p'])
leak = int(p_partially_leaked[256:].decode(), 2)
chunck_offset = 2 ** 768

x = Zmod(n)['x'].gen()
F = x * chunck_offset + leak
F = F.monic()
F = F.change_ring(ZZ)

# Lattice creation
B = matrix.identity(basis_dim)
B[0, 0] = n
B[1, 0] = F.coefficients()[0]
B[1, 1] = X
B[2, 1] = F.coefficients()[0] * X
B[2, 2] = X ** 2
B[3, 2] = F.coefficients()[0] * X ** 2
B[3, 3] = X ** 3

# LLL
lll = B.LLL()

# G polynomial construction
g_x = lll.rows()[0]
x = ZZ['x'].gen()
G = 0
for i, elem in enumerate(g_x):
    G = G + (elem / (X ** i)) * (x ** i)

roots = G.roots()
x0 = roots[0][0]
p = int(leak + (x0 * chunck_offset))

# Send the signtaure (from server code)
q = n // p
Zphi = Zmod((p-1) * (q-1))
d = 1/Zphi(e)
h = int.from_bytes(SHA256.new(b"gimme the flag").digest())
json_send({ "command": "solve", "signature": int(Zmod(n)(h) ** d), "identifier": key_id })

flag = json_recv()

if "flag" in flag:
    print(flag)

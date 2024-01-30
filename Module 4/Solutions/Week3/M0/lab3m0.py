import json
import logging
import sys
import os
import socket

# Change the port to match the challenge you're solving
PORT = 40300

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
# Reference: the provided book on Moodle. Specifically: Chapter 19
from sage.all import ZZ, Zmod, matrix
X = 2 ** 128

json_send({ "command": "get_pubkey"})
public_key = json_recv()
n = public_key["n"]
e = public_key["e"]

json_send({ "command": "get_ciphertext"})
cipher = json_recv()
ciphertext = int(cipher['ciphertext'], 16)

# Define the polynomial F. Reference: chapter 19.4.1 (and slides)
# Leaked LSBs (fixed) => from server's padding
# MSBs --> k => multiplicative coefficient for bits preceding the secret we are looking for
k = Zmod(n)["k"].gen()
F = (k * (256 ** 111) + int.from_bytes(b'\x6f' * 111)) ** e - ciphertext
F = F.monic()
F = F.change_ring(ZZ)
coefficients = F.coefficients()

# Construct the Lattice Matrix
m_dim = F.degree()
B = matrix.identity(m_dim + 1)

for i in range(m_dim):
    B[i,i] = n * (X ** i)

for i in range(m_dim):
    B[m_dim, i] = coefficients[i] * (X ** i)

B[m_dim, m_dim] = X ** m_dim

# LLL
lll = B.LLL()

# G polynomial construction
g_x = lll.rows()[0]

x = ZZ['x'].gen()
G = 0
for i, elem in enumerate(g_x):
    G = G + (elem / (X ** i)) * (x ** i)

roots = G.roots()

for root in roots:
    msg = int(root[0]).to_bytes(16).decode()
    
    json_send({"command": "solve", "message": msg})
    flag = json_recv()

    if "flag" in flag:
        print(flag)
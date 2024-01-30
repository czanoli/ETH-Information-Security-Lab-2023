import json
import logging
import sys
import os
import socket

from schnorr import Schnorr, Schnorr_Params
from sage.all import matrix, ZZ
import math

# Change the port to match the challenge you're solving
PORT = 40210

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
# Parameters of the P-256 NIST curve
a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

nistp256_params = Schnorr_Params(a, b, p, P_x, P_y, q)
schnorr = Schnorr(nistp256_params)

L = 8
n = 60
scale = 2**(L+1)
# From slide 36 week1 (lambda1). det(L)^1/n = q
M = schnorr.Z_q(schnorr.q * (math.sqrt((n + 1) / (2 * math.pi * math.e))))

s_list = list()
h_list = list()
partial_nonce_list = list()

for i in range(n):
    json_send({"command": "get_signature", "msg": f"{i}"})
    signature = json_recv()

    h = signature["h"]
    s = signature["s"]
    partial_nonce = signature["nonce"]
    
    s_list.append(s)
    h_list.append(h)
    partial_nonce_list.append(partial_nonce)

B_prime = matrix(ZZ, n+2, n+2)

for i in range(n):
    B_prime[i,i] = q

for i in range(n):
    B_prime[n, i] = h_list[i]
    
for i in range(n):
    B_prime[n+1, i] = schnorr.Z_q(partial_nonce_list[i] - s_list[i])

B_prime = B_prime * scale
B_prime[n, n] = 1
B_prime[n+1, n+1] = M

lll = B_prime.LLL()

for row in lll:
    if row[-1] == M:
        pk = schnorr.Z_q(B_prime[n+1, -2] - row[-2])
        #print(pk)
        break

h, s = schnorr.Sign(pk, "gimme the flag")

json_send({ "command": "solve", "h": int(h), "s": int(s)})

flag = json_recv()
print(flag)
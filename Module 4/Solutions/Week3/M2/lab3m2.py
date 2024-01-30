import json
import logging
import sys
import os
import socket

# Change the port to match the challenge you're solving
PORT = 40320

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
a   = 17
b   = 1
n   = 0x579d4e9590eeb88fd1b640a4d78fcf02bd5c375351cade76b69561d9922d3070d479a67192c67265cf9ae4a1efde400ed40757b0efd2912cbda49e60c83a1ddd361d31859bc4e206158491a528bd46d0b41c6e8d608c586a0788b8027f0f796e9e077766f83683fd52965101bb7bf9fd90c9e9653f02fada8bf10d62bc325ef
P_x = 0x54d73da0d9a78dc3a7914c1677def57a6f4e74c424e574f93e5252885833f988e27517b5b4da981dd69fc242d5c0dc3d17e6129c6e4af4cd2cfb8200ce49c17381d80e2dd9e3d5f0517e720a7db3d903ca11b33069edffbba39f71f6b5f8d698ab1a8170017ed6d1675175e6e54b6ebbb94da460d623b87669c8686d2d4b856
P_y = 0x30ba788b53a932136fdfdd0f82d6328a1bbb29368aa22d8fe2c2ae16a7d466f1a8d0e4b0fe725ed049c9ae41090e521add6e7e1d5f7f498942bae2a997f2f55bdd7959f5d72c3d781d657cb0feb81e7e15fd7065b3ce6f5b5cd5218e8c101841e600c1920d4e8fb3dd3aaf2458861015f652babcd32be90f46a8cdbc54edd1
from sage.all import ZZ, Zmod, matrix

def xor(a: bytes, b: bytes) -> bytes:
    if len(a) < len(b):
        a += bytes([0] * (len(b) - len(a)))

    if len(b) < len(a):
        b += bytes([0] * (len(a) - len(b)))

    return bytes(x ^ y for x, y in zip(a, b))

json_send({ "command": "get_ciphertext"})
cipher = json_recv()
ciphertext = bytes.fromhex(cipher['ciphertext'])
leaked_x = int.from_bytes(ciphertext[16:128], 'big')
leaked_y = int.from_bytes(ciphertext[128:], 'big')

# Define the polynomial F. From equation in slide 8 week1. Shift needed due to the position of the unknown part of x
X = 2 ** 128
x = Zmod(n)["x"].gen()
F = (x * (2 ** (1024 - 128)) + leaked_x)**3 + a*(x * (2 ** (1024 - 128)) + leaked_x) + b - leaked_y**2
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
    x = int((root[0] * 2 ** (1024-128) + leaked_x)).to_bytes(128)
    y = leaked_y.to_bytes(128)
    
    keystream = x + y
    
    secret = xor(ciphertext, keystream)
    
    msg = secret.split(b'\x00')[0]
    
    json_send({ "command": "solve", "plaintext": msg.decode()})
    flag = json_recv()

    if "flag" in flag:
        print(flag)

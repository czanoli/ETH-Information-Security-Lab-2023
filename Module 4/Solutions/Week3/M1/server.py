import math
import os
from dataclasses import dataclass
from Crypto.Util.number import getPrime

from sage.all import Zmod
from boilerplate import CommandServer, on_command, on_startup

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

@dataclass
class RSAKeyContainer:
    """ A helper container class to store data about an RSA key """
    identifier: str
    p: int
    q: int
    n: int
    e: int
    d: int
    bits: int

def xor(a: bytes, b: bytes) -> bytes:
    if len(a) < len(b):
        a += bytes([0] * (len(b) - len(a)))

    if len(b) < len(a):
        b += bytes([0] * (len(a) - len(b)))

    return bytes(x ^ y for x, y in zip(a, b))

class RSAExportingServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.keys = {}

        # An AES key to encrypt exported data
        self.export_key = os.urandom(16)
        self.key_exported = False
        super().__init__(*args, **kwargs)

    @on_command("gen_key")
    def generate_new_key(self, msg):
        try:
            if len(self.keys) >= 3:
                self.send_message({"error": "Upgrade to the premium plan to store more private keys!"})
                return

            bits = int(msg["bit_length"])
            if bits not in (512, 1024, 2048):
                self.send_message({"error": "Invalid bit length!"})
                return

            identifier = msg["identifier"]

            e = 65537

            while True:
                p = getPrime(bits // 2)
                q = getPrime(bits // 2)
                phi = (p-1) * (q-1)

                if math.gcd(e, phi) == 1:
                    break

            n = p * q
            Zphi = Zmod(phi)
            d = 1/Zphi(e)

            if identifier not in self.keys:
                # Create new RSA key container to hold the data
                self.keys[identifier] = RSAKeyContainer(identifier, p, q, n, e, d, bits)
            else:
                # If the container already exist, simply overwrite the value
                self.keys[identifier].p = p
                self.keys[identifier].q = q
                self.keys[identifier].n = n
                self.keys[identifier].e = e
                self.keys[identifier].d = d

            self.send_message({"res": f"Succesfully new public key for identifier {identifier}"})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})


    @on_command("get_signature")
    def handle_signature(self, msg):
        self.send_message({"error": "We finished the budget for the software development :("})


    @on_command("get_pubkey")
    def handle_getpubkey(self, msg):
        if len(self.keys) == 0:
            self.send_message({"error": "Generate a key first!"})
            return

        try:
            identifier = msg["identifier"]
            key_container = self.keys[identifier]

            self.send_message({
                "n": key_container.n,
                "e": key_container.e,
                "bits": key_container.bits
            })
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})


    @on_command("export_p")
    def handle_getp(self, msg):
        if self.key_exported:
            self.send_message({"error": "Can't export anymore!"})
            return

        try:
            identifier = msg["identifier"]
            key_container = self.keys[identifier]

            p = bin(key_container.p)[2:]
            print("THE LENGTH OF p IS: ", len(p))

            # We can't let you have the raw private key, of course...

            # Derive how long we need the encryption stream to be
            len_obfuscation = key_container.bits // 2
            cipher = AES.new(self.export_key, AES.MODE_CTR)
            keystream = cipher.encrypt(b'\x00' * len_obfuscation)

            # Use the encryption stream by XORing it with the plaintext
            p_obfuscated = xor(p.encode(), keystream)

            self.key_exported = True

            self.send_message({"nonce": cipher.nonce.hex(), "obfuscated_p": p_obfuscated.hex()}) # pyright: ignore
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})


    @on_command("solve")
    def handle_verification(self, msg):
        try:
            signature = int(msg["signature"])
            identifier = msg["identifier"]

            # Verify a simple RSA signature...

            h = int.from_bytes(SHA256.new(b"gimme the flag").digest())
            key = self.keys[identifier]

            Zn = Zmod(key.n)

            if Zn(h) == Zn(signature) ** key.e:
                self.send_message({"res": "Oh no, my secrets!", "flag": self.flag})
            else:
                self.send_message({"res": "Nah."})
                self.close_connection()
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    RSAExportingServer.start_server("0.0.0.0", 40310, flag=flag)

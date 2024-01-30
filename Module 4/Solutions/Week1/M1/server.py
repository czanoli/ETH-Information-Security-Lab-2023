import secrets
from ecdsa2 import ECDSA2, ECDSA2_Params, bits_to_int, hash_message_to_bits
from boilerplate import CommandServer, on_command

from sage.all import Zmod

# Parameters of the P-256 NIST curve
a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

nistp256_params = ECDSA2_Params(a, b, p, P_x, P_y, q)

def get_random_string() -> str:
    return secrets.token_hex(32)

class SignServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.ecdsa = ECDSA2(nistp256_params)
        self.privkey, self.pubkey = self.ecdsa.KeyGen()
        super().__init__(*args, **kwargs)

    @on_command("get_pubkey")
    def handle_getpubkey(self, msg):
        self.send_message({"x": int(self.pubkey.x), "y": int(self.pubkey.y)})

    @on_command("get_signature")
    def handle_signature(self, msg):
        try:
            h = bits_to_int(hash_message_to_bits("Now you're just some value that I used to nonce"), q)
            k = self.ecdsa.Z_q(h)
            m = msg["msg"]

            if m == "gimme the flag":
                self.send_message({"error": "Nice try, big guy"})
                return

            r, s = self.ecdsa.Sign_FixedNonce(k, self.privkey, m)

            self.send_message({"r": int(r), "s": int(s)})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

    @on_command("solve")
    def handle_verification(self, msg):
        try:
            r = self.ecdsa.Z_q(msg["r"])
            s = self.ecdsa.Z_q(msg["s"])
            if self.ecdsa.Verify(self.pubkey, "gimme the flag", r, s):
                self.send_message({"res": "Huh? how did you do that?", "flag": self.flag})
            else:
                self.send_message({"res": "Nah."})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    SignServer.start_server("0.0.0.0", 40110, flag=flag)

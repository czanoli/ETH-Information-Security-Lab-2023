import secrets
from ecdsa2 import ECDSA2, ECDSA2_Params
from boilerplate import CommandServer, on_command, on_startup

from sage.all import Zmod

# Parameters of the P-256 NIST curve
a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

nistp256_params = ECDSA2_Params(a, b, p, P_x, P_y, q)

# Number of correct guesses in a row to obtain
TARGET = 128

def get_random_string() -> str:
    return secrets.token_hex(32)

class SignServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.score = 0
        self.ecdsa = ECDSA2(nistp256_params)
        self.privkey, self.pubkey = self.ecdsa.KeyGen()
        super().__init__(*args, **kwargs)

    @on_command("get_signature")
    def handle_signature(self, msg):
        r, s = self.signature
        self.send_message({"msg": self.message, "r": int(r), "s": int(s)})

    @on_command("get_pubkey")
    def handle_getpubkey(self, msg):
        self.send_message({"x": int(self.pubkey.x), "y": int(self.pubkey.y)})

    @on_startup()
    def initialize_new_round(self):
        self.message = get_random_string()

        # Toss a coin (to your adversary)
        self.correct_signature = secrets.randbits(1)

        if self.correct_signature:
            r, s = self.ecdsa.Sign(self.privkey, self.message)
        else:
            # A corrupted signature is a tuple of random field elements
            Z_p = Zmod(self.ecdsa.p)
            r = Z_p.random_element()
            s = Z_p.random_element()

        self.signature = (r, s)


    @on_command("solve")
    def handle_guess(self, msg):
        try:
            b = msg["b"]

            # We expect a guess of b=1 if the signature verifies
            if b == self.correct_signature:
                self.score += 1
                self.initialize_new_round()
                self.send_message({"res": f"Good! ({self.score}/{TARGET})"})
            else:
                self.send_message({"res": "This ain't it chief."})
                self.close_connection()
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

    @on_command("flag")
    def handle_flag(self, msg):
        if self.score >= TARGET:
            self.send_message({"flag": self.flag})
            return

        self.send_message({"res": "Not enough correct guesses!"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    SignServer.start_server("0.0.0.0", 40102, flag=flag)

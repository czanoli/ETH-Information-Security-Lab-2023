import secrets
from ecdsa2 import ECDSA2, ECDSA2_Params, Point
from boilerplate import CommandServer, on_command

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

class VfyServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.ecdsa = ECDSA2(nistp256_params)
        super().__init__(*args, **kwargs)

    @on_command("get_challenge")
    def handle_signature(self, msg):
        try:
            x = msg["x"]
            y = msg["y"]
            self.pubkey = Point(self.ecdsa.curve, x, y)
            self.message = get_random_string()
            self.send_message({"msg": self.message})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

    @on_command("solve")
    def handle_guess(self, msg):
        try:
            r = self.ecdsa.Z_q(msg["r"])
            s = self.ecdsa.Z_q(msg["s"])
            if self.ecdsa.Verify(self.pubkey, self.message, r, s):
                self.send_message({"flag": self.flag})
            else:
                self.send_message({"res": "Nah."})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    VfyServer.start_server("0.0.0.0", 40103, flag=flag)

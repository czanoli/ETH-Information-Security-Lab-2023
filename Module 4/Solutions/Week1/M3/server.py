import secrets
from schnorr import Schnorr, Schnorr_Params
from boilerplate import CommandServer, on_command
from timing import Timer
import string
import random

num_signatures = 20
num_leading_zeros = 6
max_querries = 20000
max_message_length = 512

# Parameters of the P-256 NIST curve
a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

nistp256_params = Schnorr_Params(a, b, p, P_x, P_y, q)

def get_random_string(max_len):
    # this does not need to be cryptographic randomness
    lengths = range(1, max_len+1)
    ascii_symbols = string.ascii_letters + string.digits
    weights = [len(ascii_symbols)**i for i in range(max_len)]
    length = random.choices(lengths, weights=weights)[0]
    return "".join(random.choices(ascii_symbols, k=length))

class SignServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.schnorr = Schnorr(nistp256_params)
        self.privkey, self.pubkey = self.schnorr.KeyGen()

        self.queries = 0

        # An unguessable secret...
        self.secret = secrets.token_hex(16)
        super().__init__(*args, **kwargs)

    @on_command("get_pubkey")
    def handle_getpubkey(self, msg):
        self.send_message({"x": int(self.pubkey.x), "y": int(self.pubkey.y)})

    @on_command("get_signature")
    def handle_signature(self, msg):
        if self.queries == max_querries:
            self.send_message({"error": "Maximum number of signature queries reached"})
            self.close_connection()
            return
        try:
            m = get_random_string(128)
            timer = Timer()
            timer.tic()
            k = self.schnorr.generate_deterministic_nonce(m, self.privkey)
            h, s = self.schnorr.Sign_FixedNonce(k, self.privkey, m)
            t = timer.toc()
            self.queries += 1
            self.send_message({"h": int(h), "s": int(s), "msg": m, "time":int(t)})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

    @on_command("solve")
    def handle_verification(self, msg):
        try:
            msgs = list(set(msg["messages"]))

            if len(msgs) < num_signatures:
                self.send_message({"error": f"You send {len(msgs)} values, expected {num_signatures}."})
                return
            nonces = [self.schnorr.generate_deterministic_nonce(m, self.privkey) for m in msgs[:num_signatures]]
            if any(int(nonce).bit_length() > 256-num_leading_zeros for nonce in nonces):
                self.send_message({"res": f"Nah. {sum([int(nonce).bit_length() > 256-num_leading_zeros for nonce in nonces])}"})
            else:
                self.send_message({"res": "Huh? how did you do that?", "flag": self.flag})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    SignServer.start_server("0.0.0.0", 40130, flag=flag)

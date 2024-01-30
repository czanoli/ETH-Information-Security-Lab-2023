import secrets
from boilerplate import CommandServer, on_command
from sage.all import EllipticCurve, Zmod, crt, random_prime

# Parameters of our special, totally not backdoored, curve
N_BIT_LENGTH = 1024
N_BYTE_LENGTH = N_BIT_LENGTH // 8

a   = 17
b   = 1
n   = 0x579d4e9590eeb88fd1b640a4d78fcf02bd5c375351cade76b69561d9922d3070d479a67192c67265cf9ae4a1efde400ed40757b0efd2912cbda49e60c83a1ddd361d31859bc4e206158491a528bd46d0b41c6e8d608c586a0788b8027f0f796e9e077766f83683fd52965101bb7bf9fd90c9e9653f02fada8bf10d62bc325ef
P_x = 0x54d73da0d9a78dc3a7914c1677def57a6f4e74c424e574f93e5252885833f988e27517b5b4da981dd69fc242d5c0dc3d17e6129c6e4af4cd2cfb8200ce49c17381d80e2dd9e3d5f0517e720a7db3d903ca11b33069edffbba39f71f6b5f8d698ab1a8170017ed6d1675175e6e54b6ebbb94da460d623b87669c8686d2d4b856
P_y = 0x30ba788b53a932136fdfdd0f82d6328a1bbb29368aa22d8fe2c2ae16a7d466f1a8d0e4b0fe725ed049c9ae41090e521add6e7e1d5f7f498942bae2a997f2f55bdd7959f5d72c3d781d657cb0feb81e7e15fd7065b3ce6f5b5cd5218e8c101841e600c1920d4e8fb3dd3aaf2458861015f652babcd32be90f46a8cdbc54edd1
curve = EllipticCurve(Zmod(n), [a, b])

# NOTE: this function has been used to generate the parameters above.
# This is in case you'd like to be able to generate them for yourself locally
def generate_parameters(a: int | None = 17, b: int | None = 1):
    p = random_prime(2 ** (N_BIT_LENGTH // 2))
    q = random_prime(2 ** (N_BIT_LENGTH // 2))
    n = p * q
    Zn = Zmod(n)
    Zp = Zmod(p)
    Zq = Zmod(q)

    a = a or Zn.random_element()
    b = b or Zn.random_element()

    while True:
        x = Zn.random_element()
        y_squared = x**3 + a * x + b

        # Computing roots mod N is computationally infeasible
        # However, we know the factorization, so we can reduce to two sub-problems
        # and use the chinese remainder theorem to obtain the square root
        if Zp(y_squared).is_square() and Zq(y_squared).is_square():
            y_modp = Zp(y_squared).sqrt()
            y_modq = Zq(y_squared).sqrt()
            y = crt([int(y_modp), int(y_modq)], [p, q])
            break

    return a, b, n, x, y

def xor(a: bytes, b: bytes) -> bytes:
    if len(a) < len(b):
        a += bytes([0] * (len(b) - len(a)))

    if len(b) < len(a):
        b += bytes([0] * (len(a) - len(b)))

    return bytes(x ^ y for x, y in zip(a, b))

class SignServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.secret = secrets.token_hex(8)
        self.base_point = curve(P_x, P_y)

        # Hint: this is NOT the vulnerability.
        self.privkey = secrets.randbelow(n)
        self.pubkey = self.privkey * self.base_point

        self.ciphertext_received = False

        super().__init__(*args, **kwargs)

    @on_command("get_ciphertext")
    def handle_encryption(self, msg):
        """Implements encryption of the secret message"""

        if self.ciphertext_received:
            self.send_message({"error": "Leave some for others!"})
            return

        ephkey = secrets.randbelow(n)
        eph_pubkey = ephkey * self.base_point
        secret_point = ephkey * self.pubkey

        x_coord = int(secret_point[0]).to_bytes(N_BYTE_LENGTH)
        y_coord = int(secret_point[1]).to_bytes(N_BYTE_LENGTH)

        keystream = x_coord + y_coord
        
        print(keystream)

        ciphertext = xor(keystream, self.secret.encode())
        
        print(ciphertext)

        self.send_message({"keystream": keystream.hex(), "ciphertext": ciphertext.hex()})
        self.ciphertext_received = True

    @on_command("solve")
    def handle_solve(self, msg):
        try:
            ptxt = msg["plaintext"]
            if ptxt == self.secret:
                self.send_message({"res": "Huh? how did you do that?", "flag": self.flag})
            else:
                self.send_message({"res": "Nah."})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    SignServer.start_server("0.0.0.0", 40320, flag=flag)

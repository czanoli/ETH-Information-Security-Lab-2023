from math import gcd
import secrets
from boilerplate import CommandServer, on_command, on_startup

from Crypto.Util.number import getPrime
from sage.all import Zmod

N_BIT_LENGTH = 1024

def get_random_string() -> str:
    return secrets.token_hex(8)

class RSAEncServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag

        while True:
            self.p = getPrime(N_BIT_LENGTH // 2)
            self.q = getPrime(N_BIT_LENGTH // 2)
            self.e = 3
            if gcd(self.e, (self.p - 1) * (self.q - 1)) == 1:
                break

        self.n = self.p * self.q

        self.Zn = Zmod(self.n)
        super().__init__(*args, **kwargs)

    @on_startup()
    def handle_startup(self):
        self.secret_message = get_random_string()

    @on_command("get_pubkey")
    def handle_getpubkey(self, msg):
        self.send_message({"n": int(self.n), "e": int(self.e)})

    @on_command("get_ciphertext")
    def handle_ciphertext(self, msg):
        # I've been told that I have to use PKCS7 for cryptography...

        # Padding
        padded_ptxt = b'\x00' + self.secret_message.encode()
        print(self.secret_message.encode())
        to_add = N_BIT_LENGTH // 8 - len(padded_ptxt)
        print(to_add)
        padded_ptxt += bytes([to_add] * to_add)
        ptxt_int = int.from_bytes(padded_ptxt)

        # Encrypt
        ctxt_int = self.Zn(ptxt_int) ** self.e

        # Encode and send
        ctxt_bytes = int(ctxt_int).to_bytes(N_BIT_LENGTH // 8)
        self.send_message({"ciphertext": ctxt_bytes.hex()})


    @on_command("solve")
    def handle_verification(self, msg):
        try:
            guess = msg["message"]
            print(guess, self.secret_message)
            if guess == self.secret_message:
                self.send_message({"res": "Oh no, my secrets!", "flag": self.flag})
            else:
                self.send_message({"res": "Nah."})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    RSAEncServer.start_server("0.0.0.0", 40300, flag=flag)
